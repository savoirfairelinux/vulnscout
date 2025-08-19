import os


class SetStatus:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.status_file = os.path.join(self.base_dir, "status.txt")

    def set_status(self, step, message, progress):
        with open(self.status_file, "a") as f:
            f.write(f"{step} {message} {progress}\n")
