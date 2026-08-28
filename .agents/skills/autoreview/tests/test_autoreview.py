from __future__ import annotations

import importlib.machinery
import unittest
from pathlib import Path
from unittest import mock


HELPER = Path(__file__).parents[1] / "scripts" / "autoreview"
AUTOREVIEW = importlib.machinery.SourceFileLoader("repo_autoreview", str(HELPER)).load_module()


class RepoAdaptationTest(unittest.TestCase):
    def test_feature_branch_defaults_to_integration_base(self) -> None:
        with (
            mock.patch.object(AUTOREVIEW, "current_branch", return_value="feat/review"),
            mock.patch.object(AUTOREVIEW, "is_dirty", return_value=False),
            mock.patch.object(AUTOREVIEW, "detect_pr_base", return_value=None),
        ):
            self.assertEqual(
                AUTOREVIEW.choose_target(Path("."), "auto", None),
                ("branch", "origin/main"),
            )

    def test_clean_primary_branch_requires_explicit_target(self) -> None:
        for branch in ("main", "dev", "develop"):
            with (
                self.subTest(branch=branch),
                mock.patch.object(AUTOREVIEW, "current_branch", return_value=branch),
                mock.patch.object(AUTOREVIEW, "is_dirty", return_value=False),
            ):
                with self.assertRaisesRegex(SystemExit, "clean primary-branch"):
                    AUTOREVIEW.choose_target(Path("."), "auto", None)

    def test_range_requires_base_and_preserves_exact_base(self) -> None:
        with self.assertRaisesRegex(SystemExit, "requires --base"):
            AUTOREVIEW.choose_target(Path("."), "range", None)

        self.assertEqual(
            AUTOREVIEW.choose_target(Path("."), "range", "base-sha"),
            ("range", "base-sha"),
        )

    def test_explicit_branch_rejects_dirty_worktree(self) -> None:
        with (
            mock.patch.object(AUTOREVIEW, "current_branch", return_value="feat/review"),
            mock.patch.object(AUTOREVIEW, "is_dirty", return_value=True),
        ):
            with self.assertRaisesRegex(SystemExit, "clean worktree"):
                AUTOREVIEW.choose_target(Path("."), "branch", "origin/main")

    def test_range_paths_use_two_ref_diff(self) -> None:
        with mock.patch.object(AUTOREVIEW, "git", return_value="a.ts\nb.ts\n") as git:
            paths = AUTOREVIEW.review_paths(Path("."), "range", "base-sha", "unused", "head-sha")

        self.assertEqual(paths, {"a.ts", "b.ts"})
        git.assert_called_once_with(Path("."), "diff", "--name-only", "base-sha", "head-sha")

    def test_merge_commit_paths_use_first_parent(self) -> None:
        with (
            mock.patch.object(AUTOREVIEW, "commit_parents", return_value=["parent-one", "parent-two"]),
            mock.patch.object(AUTOREVIEW, "git", return_value="merged.ts\n") as git,
        ):
            paths = AUTOREVIEW.review_paths(Path("."), "commit", None, "merge-sha", "unused")

        self.assertEqual(paths, {"merged.ts"})
        git.assert_called_once_with(Path("."), "diff", "--name-only", "parent-one", "merge-sha")

    def test_p0_filter_removes_wider_findings(self) -> None:
        report = {
            "findings": [
                {"priority": "P0"},
                {"priority": "P1"},
                {"priority": "P3"},
            ],
            "overall_correctness": "patch is incorrect",
            "overall_explanation": "Review complete.",
        }

        AUTOREVIEW.filter_findings_by_priority(report, "P0")

        self.assertEqual(report["findings"], [{"priority": "P0"}])
        self.assertEqual(report["overall_correctness"], "patch is incorrect")
        self.assertIn("Omitted 2", report["overall_explanation"])

    def test_threshold_prompt_names_included_priorities(self) -> None:
        prompt = AUTOREVIEW.priority_prompt("P1")
        self.assertIn("report only P0, P1", prompt)
        self.assertNotIn("P2", prompt)


if __name__ == "__main__":
    unittest.main()
