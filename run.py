from tkinter import *
from pyshark.frontend_pkg import AppWindow

if __name__ == "__main__":
    """
    run.py is a main file which puts all functions and
    classes together and runs them.
    """

    window = Tk()

    myApp = AppWindow(window)
    myApp.add_buttons()
    myApp.add_text_box()
    myApp.add_filter_fields()

    window.title("PyShark Packet Sniffer")
    window.grid_columnconfigure(0, weight=1)
    window.grid_rowconfigure(0, weight=1)

    window.mainloop()
