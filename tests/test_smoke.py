import os
import subprocess


def test_readme_exists():
    assert os.path.isfile("README.md")


def test_gitignore_exists():
    assert os.path.isfile(".gitignore")


def test_pkl_not_tracked():
    result = subprocess.run(
        ["git", "ls-files", "attack_detection_model.pkl"],
        capture_output=True, text=True
    )
    assert result.stdout.strip() == "", f"PKL file still tracked: {result.stdout.strip()}"
