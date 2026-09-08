"""Exercise the screenshot gate against real staged blobs and ExifTool."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts/check-screenshots.sh"
IMAGE = ROOT / "static/favicon-32x32.png"


@unittest.skipUnless(shutil.which("exiftool"), "ExifTool is required")
class ScreenshotGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.run_command("git", "init", "-q")

    def run_command(self, *args):
        return subprocess.run(args, cwd=self.repo, check=True, capture_output=True, text=True)

    def image(self, name="shot.png", oversized=False, artist=False):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(IMAGE, path)
        self.run_command("exiftool", "-all=", "-overwrite_original", str(path))
        if artist:
            self.run_command("exiftool", "-Artist=Private Author", "-overwrite_original", str(path))
        if oversized:
            with path.open("ab") as stream:
                stream.write(b"\0" * (2 * 1024 * 1024))
        return path

    def stage(self, name):
        self.run_command("git", "add", "--", name)

    def gate(self, blocked):
        result = subprocess.run(["bash", str(HOOK)], cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1 if blocked else 0, result.stdout + result.stderr)
        return result.stderr

    def test_staged_oversized_image_cannot_pass_after_unstaged_resize(self):
        self.image(oversized=True)
        self.stage("shot.png")
        self.image()
        self.assertIn("exceeds", self.gate(blocked=True))

    def test_unstaged_large_copy_does_not_block_small_staged_image(self):
        self.image()
        self.stage("shot.png")
        self.image(oversized=True)
        self.gate(blocked=False)

    def test_unstaged_scrub_does_not_hide_staged_metadata(self):
        self.image(artist=True)
        self.stage("shot.png")
        self.image()
        self.assertIn("Artist", self.gate(blocked=True))

    def test_deleted_working_copy_still_checks_staged_bytes(self):
        path = self.image(oversized=True)
        self.stage("shot.png")
        path.unlink()
        self.assertIn("exceeds", self.gate(blocked=True))

    def test_space_and_newline_filenames_are_checked(self):
        name = "capture with\na newline.png"
        self.image(name, artist=True)
        self.stage(name)
        self.assertIn("Artist", self.gate(blocked=True))

    def test_rename_into_raw_directory_is_blocked(self):
        self.image()
        self.stage("shot.png")
        self.run_command("git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                         "commit", "-qm", "fixture")
        (self.repo / "screenshots-raw").mkdir()
        self.run_command("git", "mv", "shot.png", "screenshots-raw/shot.png")
        self.assertIn("raw capture", self.gate(blocked=True))

    def test_no_staged_images_passes(self):
        self.gate(blocked=False)


if __name__ == "__main__":
    unittest.main()
