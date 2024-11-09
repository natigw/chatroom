import sys
import threading
import time
import msvcrt


class CustomInput:
    def __init__(self):
        self.input_buffer = ""
        self.last_fully_entered_input = ""
        self.done = False
        self.lock = threading.Lock()

    def _capture_input(self, mask = ""):
        while not self.done:
            time.sleep(0.05)
            if msvcrt.kbhit():
                char = msvcrt.getch()
                if char == b'\r':  # Enter key
                    with self.lock:
                        self.done = True
                elif char == b'\x08':  # Backspace
                    with self.lock:
                        if len(self.input_buffer) > 0:
                            self.input_buffer = self.input_buffer[:-1]
                            sys.stdout.write('\b \b')  # Erase last character
                            sys.stdout.flush()
                else:
                    with self.lock:
                        self.input_buffer += char.decode('utf-8')
                        if mask == "":
                            sys.stdout.write(char.decode('utf-8'))
                        else:
                            sys.stdout.write(mask)
                        sys.stdout.write(char.decode('utf-8'))
                        sys.stdout.flush()

    def input(self, prompt="", mask=""):
        self.last_fully_entered_input = self.input_buffer
        self.input_buffer = ""
        self.done = False

        sys.stdout.write(prompt)
        sys.stdout.flush()

        capture_thread = threading.Thread(target=self._capture_input, args=(mask,))
        capture_thread.start()

        while not self.done:
            time.sleep(0.1)

        capture_thread.join()

        return self.input_buffer


    def get_current_input(self):
        with self.lock:
            return self.input_buffer

