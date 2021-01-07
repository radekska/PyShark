import sys
import time
import threading
import tkinter as tk
from tkinter import ttk
from pyshark.backend_pkg import Sniff, Insert


class AppWindow(object):
    """
    AppWindow class takes one parameter which is a Tkinter object.
    It builds whole frontend_pkg interface and implement multithreading
    solutions.

    """

    def __init__(self, window):

        """Class constructor, takes one (Tkinter object) parameter """

        self.sniffed = Sniff()
        self.insert = Insert()
        self.thread_running = bool
        self.json_data = []

        self.master_frame = tk.Frame(window, bg="gray13", bd=3, relief=tk.RIDGE)
        self.master_frame.grid(sticky=tk.NSEW)
        self.master_frame.grid_columnconfigure(0, weight=1)
        self.master_frame.grid_rowconfigure(3, weight=1)

    def add_filter_fields(self):
        """This method adds filter fields in AppWindow object"""

        filter_frame = tk.Frame(self.master_frame, bg="gray13", pady=10)
        filter_frame.grid(row=2, column=0, sticky=tk.NSEW)

        ip_options = ["All", "IPv4", "IPv6"]
        tprotocol_options = ["All", "TCP", "UDP", "ICMP", "SCTP"]

        self.choice_ip = tk.StringVar(filter_frame)
        self.choice_ip.set(ip_options[0])  # default value

        self.choice_prot = tk.StringVar(filter_frame)
        self.choice_prot.set(tprotocol_options[0])  # default value

        filter_label = tk.Label(filter_frame, text="Filter by:", font=("Courier", 12), bg='grey13', foreground="gray99")
        filter_label.grid(row=0, column=0, padx=10)

        filter_menu_ip = tk.OptionMenu(filter_frame, self.choice_ip, *ip_options)
        filter_menu_ip.grid(row=0, column=1, padx=10)
        filter_menu_ip.config(font=("Courier", 12), bg='grey13', width=12, foreground="gray99")
        filter_menu_ip['menu'].config(font=("Courier", 12), bg='grey13', foreground="gray99")

        filter_menu_prot = tk.OptionMenu(filter_frame, self.choice_prot, *tprotocol_options)
        filter_menu_prot.grid(row=0, column=2, padx=10)
        filter_menu_prot.config(font=("Courier", 12), bg='grey13', width=12, foreground="gray99")
        filter_menu_prot['menu'].config(font=("Courier", 12), bg='grey13', foreground="gray99")

    def add_buttons(self):
        """This method adds button fields in AppWindow object"""

        button_frame = tk.Frame(self.master_frame, bg="gray13")
        button_frame.grid(row=1, column=0, sticky=tk.NSEW)
        b_run = tk.Button(button_frame, text="Run sniffing", width=12, command=self.sniff_button, font=("Courier", 12),
                          bg="grey13", foreground="gray99")
        b_run.grid(row=1, column=0, padx=5)
        b_stop = tk.Button(button_frame, text="Stop", width=12, command=self.stop_button, font=("Courier", 12),
                           bg="grey13", foreground="gray99")
        b_stop.grid(row=1, column=1, padx=5)
        b_clear = tk.Button(button_frame, text="Clear ", width=12, command=self.clr_button, font=("Courier", 12),
                            bg="grey13", foreground="gray99")
        b_clear.grid(row=1, column=2, padx=5)
        b_quit = tk.Button(button_frame, text="Quit", width=12, command=self.quit_button, font=("Courier", 12),
                           bg="grey13", foreground="gray99")
        b_quit.grid(row=1, column=3, padx=5)

        button_frame.grid_rowconfigure(2, weight=1)
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_columnconfigure(2, weight=1)

    def add_text_box(self):
        """This method adds text box field in AppWindow object"""


        scroll_frame = tk.Frame(self.master_frame)
        scroll_frame.grid(row=3, column=0, sticky=tk.NSEW)

        self.text_box = tk.ttk.Treeview(scroll_frame)
        self.text_box.grid(row=0, column=0, sticky=tk.NSEW)

        style = tk.ttk.Style()
        style.configure("Treeview", highlightthickness=0, bd=0, font=("Courier", 12), foreground="gray99", rowheight=25,
                        bg="gray13", fieldbackground="gray13", highlightcolor="gray13")
        style.configure("Treeview.Heading", font=("Courier", 15), background="gray35", foreground="gray1",
                        relief="flat", highlightcolor="gray13")

        scroll_frame.grid_rowconfigure(0, weight=1)
        scroll_frame.grid_columnconfigure(0, weight=1)

        self.text_box["columns"] = (1, 2, 3, 4, 5, 6)
        self.text_box.column("#0", width=390, minwidth=90, stretch=tk.NO)
        self.text_box.column(1, width=200, minwidth=150, stretch=tk.NO)
        self.text_box.column(2, width=200, minwidth=200, stretch=tk.NO)
        self.text_box.column(3, width=200, minwidth=50, stretch=tk.NO)
        self.text_box.column(4, width=200, minwidth=50, stretch=tk.NO)
        self.text_box.column(5, width=200, minwidth=90, stretch=tk.NO)
        self.text_box.column(6, width=300, minwidth=150, stretch=tk.YES)

        self.text_box.heading("#0", text="|No.", anchor=tk.W)
        self.text_box.heading(1, text="|Time", anchor=tk.W)
        self.text_box.heading(2, text="|Source", anchor=tk.W)
        self.text_box.heading(3, text="|Destination", anchor=tk.W)
        self.text_box.heading(4, text="|Protocol", anchor=tk.W)
        self.text_box.heading(5, text="|Length", anchor=tk.W)
        self.text_box.heading(6, text="|Info", anchor=tk.W)

        scrollbar_y = tk.Scrollbar(scroll_frame, orient=tk.VERTICAL, width=15, bg="gray13")
        scrollbar_y.config(command=self.text_box.yview)
        scrollbar_y.grid(row=0, column=1, sticky=tk.NS)
        self.text_box.configure(yscrollcommand=scrollbar_y.set)

        scrollbar_x = tk.Scrollbar(scroll_frame, orient=tk.HORIZONTAL, width=15, bg="gray13")
        scrollbar_x.config(command=self.text_box.xview)
        scrollbar_x.grid(row=1, column=0, sticky=tk.EW)
        self.text_box.configure(xscrollcommand=scrollbar_x.set)

    def sniff_button(self):
        """This method implements sniff (start) button"""

        self.sniffed.thread_kill = True
        self.thread_print = threading.Thread(target=self.print_data)
        self.thread_print.start()

    def stop_button(self):
        """This method implements stop button"""

        self.sniffed.thread_kill = False

    def print_data(self):
        """
        This method prints all the sniffed data, formats them in to "tree rows"
        and prints them in GUI
        """

        while self.sniffed.thread_kill:
            options = [self.choice_ip.get(), self.choice_prot.get()]
            data_dict = self.sniffed.run_sniff(options)
            if data_dict is None:
                continue
            else:
                for row in data_dict.items():
                    self.insert.unpack_and_insert(row, self.text_box, self.sniffed.thread_kill)

    def clr_button(self):
        """This method implements clear button"""

        self.text_box.delete(*self.text_box.get_children())

    def quit_button(self):
        """This method implements quit button"""

        self.sniffed.thread_kill = False
        time.sleep(2)
        self.master_frame.quit()
        sys.exit()
