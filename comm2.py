import tkinter as tk
from tkinter import messagebox
from tkinter import PhotoImage
import sqlite3
from PIL import ImageTk, Image
import hashlib

# Create a database connection
conn = sqlite3.connect('complaints.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS solved_problems
             (complaint_id INTEGER PRIMARY KEY, complaint TEXT)''')


# Commit changes and close connection
conn.commit()
conn.close()

def change_password_page(parent_window, validate_login, update_password_in_database, role):
    def change_password():
        current_username = current_username_entry.get()
        current_password = current_password_entry.get()
        new_password = new_password_entry.get()
        re_enter_password = re_enter_password_entry.get()

        # Check if new password matches the re-entered password
        if new_password != re_enter_password:
            messagebox.showerror("Error", "New Password and Re-entered Password do not match.")
            return

        # Validate current password from the database
        if not validate_login(current_username, current_password, role):
            messagebox.showerror("Error", "Incorrect Current Password.")
            return

        # Update password in the database
        update_password_in_database(current_username, new_password)

        # Clear entry fields
        current_username_entry.delete(0, tk.END)
        current_password_entry.delete(0, tk.END)
        new_password_entry.delete(0, tk.END)
        re_enter_password_entry.delete(0, tk.END)

        messagebox.showinfo("Success", "Password updated successfully.")

    change_password_window = tk.Toplevel(parent_window)
    change_password_window.iconbitmap(r"C:\Users\manju\OneDrive\Desktop\wise\free-book-1210-450385.ico")
    change_password_window.title("Change Password")
    change_password_window.geometry("3000x1000")
    change_password_background = Image.open(r"C:\Users\manju\OneDrive\Desktop\wise\password.png")
    change_password_background = change_password_background.resize((1500, 1000))  # Resize image to fit window
    change_password_background_photo = ImageTk.PhotoImage(change_password_background)
    background_label = tk.Label(change_password_window, image=change_password_background_photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    background_label.image = change_password_background_photo

    def on_close():
        parent_window.deiconify()
        change_password_window.destroy()

    change_password_window.protocol("WM_DELETE_WINDOW", on_close)
    change_password_label = tk.Label(change_password_window, text="Reset Your Password", font=("Algerian", 20), bg='#f9f9f9')
    change_password_label.place(x=70,y=100)

    current_username_label = tk.Label(change_password_window, text="Username:", font=("Helvetica", 20),bg = "#f9f9f9")
    current_username_label.place(x=70,y=200)
    current_username_entry = tk.Entry(change_password_window, font=("Helvetica", 20))
    current_username_entry.place(x=400,y=200)
    current_password_label = tk.Label(change_password_window, text="Current Password:", font=("Helvetica", 20),bg = "#f9f9f9")
    current_password_label.place(x=70,y=300)
    current_password_entry = tk.Entry(change_password_window, show="*", font=("Helvetica", 20))
    current_password_entry.place(x=400,y=300)

    new_password_label = tk.Label(change_password_window, text="New Password:", font=("Helvetica", 20),bg="#f9f9f9")
    new_password_label.place(x=70,y=400)
    new_password_entry = tk.Entry(change_password_window, show="*", font=("Helvetica", 20))
    new_password_entry.place(x=400,y=400)
    re_enter_password_label = tk.Label(change_password_window, text="Re-enter New Password:", font=("Helvetica", 20),bg="#f9f9f9")
    re_enter_password_label.place(x=70,y=500)
    re_enter_password_entry = tk.Entry(change_password_window, show="*", font=("Helvetica", 20))
    re_enter_password_entry.place(x=400,y=500)
    confirm_changes_button = tk.Button(change_password_window, text="Confirm Changes", command=change_password, font=("Helvetica", 14))
    confirm_changes_button.place(x=400,y=600)


def show_admin_page():
    def validate_login(username, password, role):
        conn = sqlite3.connect('complaints.db')
        c = conn.cursor()
        # Check if the entered credentials exist in the admins table
        c.execute("SELECT * FROM admins WHERE username=? AND password=?", (username, password))
        admin = c.fetchone()
        conn.close()
        return admin
    
    def update_password_in_database(username, new_password):
        # Function to update password in the database
        conn = sqlite3.connect('complaints.db')
        c = conn.cursor()
        c.execute("UPDATE admins SET password=? WHERE username=?", (new_password, username))
        conn.commit()
        conn.close()
    def transfer_to_solved(complaint):
        # Function to transfer a complaint to the solved problems table
        conn = sqlite3.connect('complaints.db')
        c = conn.cursor()
        c.execute("INSERT INTO solved_problems (complaint) VALUES (?)", (complaint,))
        c.execute("DELETE FROM complaints WHERE complaint=?", (complaint,))
        conn.commit()
        conn.close()
    def open_view_solved_page():
        # Function to open a new window displaying solved complaints
        view_solved_page = tk.Toplevel(admin_window)
        view_solved_page.iconbitmap(r"C:\Users\manju\OneDrive\Desktop\wise\free-book-1210-450385.ico")
        view_solved_page.title("View Solved Problems")
        view_solved_page.geometry("3000x1000")
        view_solved_page_background = Image.open(r"C:\Users\manju\OneDrive\Desktop\wise\solved.png")
        view_solved_page_background = view_solved_page_background.resize((1500, 1000))  # Resize image to fit window
        view_solved_page_background_photo = ImageTk.PhotoImage(view_solved_page_background)
        background_label = tk.Label(view_solved_page, image=view_solved_page_background_photo)
        background_label.place(x=0, y=0, relwidth=1, relheight=1)
        background_label.image = view_solved_page_background_photo
        admin_label = tk.Label(view_solved_page, text="Solved Complaints", font=("Algerian", 20), bg='#f4f4f4')
        admin_label.place(x=980,y=50)


        
        solved_listbox = tk.Listbox(view_solved_page, width=50, height=25, font=("Helvetica", 16))
        solved_listbox.place(x=860,y=100)
        
        conn = sqlite3.connect('complaints.db')
        c = conn.cursor()
        c.execute("SELECT complaint FROM solved_problems")
        solved_problems = c.fetchall()
        conn.close()

        for complaint in solved_problems:
            solved_listbox.insert(tk.END, complaint[0])
    

    def insert_user(username, password):
        conn = sqlite3.connect('complaints.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()

    def open_insert_page():
        insert_page = tk.Toplevel(admin_window)
        insert_page.iconbitmap(r"C:\Users\manju\OneDrive\Desktop\wise\free-book-1210-450385.ico")
        insert_page.title("Insert Student Username and Password")
        insert_page.geometry("3000x1000")
        insert_background = Image.open(r"C:\Users\manju\OneDrive\Desktop\wise\insert.png")
        insert_background = insert_background.resize((1500, 1000))  # Resize image to fit window
        insert_background_photo = ImageTk.PhotoImage(insert_background)
        # Create a label with the background image
        background_label = tk.Label(insert_page, image=insert_background_photo)
        background_label.place(x=0, y=0, relwidth=1, relheight=1)
        # Ensure the image is not garbage collected
        background_label.image = insert_background_photo
        
        # Entry fields for new username and password
        insert_label = tk.Label(insert_page, text="Add New User", font=("Algerian", 20), bg='#d6dadf')
        insert_label.place(x=900,y=100)
        new_username_label = tk.Label(insert_page, text="New Username:", font=("Helvetica", 20),bg = '#d6dadf')
        new_username_label.place(x=900,y=200)
        new_username_entry = tk.Entry(insert_page, font=("Helvetica", 20))
        new_username_entry.place(x=1150,y=200)

        new_password_label = tk.Label(insert_page, text="New Password:", font=("Helvetica", 20),bg = '#d6dadf')
        new_password_label.place(x=900,y=300)
        new_password_entry = tk.Entry(insert_page, show="*", font=("Helvetica", 20))
        new_password_entry.place(x=1150,y=300)

        def add_user():
            # Function to add new user with username and password to the database
            username = new_username_entry.get()
            password = new_password_entry.get()
            if username and password:
                insert_user(username, password)
                messagebox.showinfo("Success", "User added successfully.")
                new_username_entry.delete(0, tk.END)
                new_password_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", "Please enter both username and password.")

        add_user_button = tk.Button(insert_page, text="Add User", command=add_user, font=("Helvetica", 20))
        add_user_button.place(x=1150,y=500)


    admin_window = tk.Toplevel(root)
    admin_window.iconbitmap(r"C:\Users\manju\OneDrive\Desktop\wise\free-book-1210-450385.ico")
    admin_window.title("Admin Page")
    admin_window.geometry("3000x1000")
    admin_window.configure(background='lightblue') 
    
    #admin_window.resizable(False, False)
    Admin_background = Image.open(r"C:\Users\manju\OneDrive\Desktop\wise\admin.png")
    Admin_background = Admin_background.resize((1500, 1000))  # Resize image to fit window
    Admin_background_photo = ImageTk.PhotoImage(Admin_background)

    # Create a label with the background image
    background_label = tk.Label(admin_window, image=Admin_background_photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    # Ensure the image is not garbage collected
    background_label.image = Admin_background_photo
    
    admin_label = tk.Label(admin_window, text="Welcome to the Administrative Page!", font=("Algerian", 20), bg='lightblue')
    admin_label.place(x=550,y=100)
    insert_button = tk.Button(admin_window, text="Insert Student", command=open_insert_page, font=("Helvetica", 16), bg='white')
    insert_button.place(x=100, y=200)

    change_password_button = tk.Button(admin_window, text="Change Password", command=lambda: change_password_page(admin_window, validate_login, update_password_in_database, "Admin"), font=("Helvetica", 16), bg='white')
    change_password_button.place(x=100, y=300)
    solved_button = tk.Button(admin_window, text="View Solved Problems", command=open_view_solved_page, font=("Helvetica", 16))
    solved_button.place(x=100,y=400)

    # Listbox to display complaints
    complaint_listbox = tk.Listbox(admin_window, width=50, height=15,font=("Helvetica", 16))
    complaint_listbox.place(x=550,y=200)

    # Fetch complaints from the database and populate the listbox
    conn = sqlite3.connect('complaints.db')
    c = conn.cursor()
    c.execute("SELECT complaint FROM complaints")
    complaints = c.fetchall()
    conn.close()

    for complaint in complaints:
        complaint_listbox.insert(tk.END, complaint[0])

    def transfer_complaint():
        # Transfer selected complaint from complaints to solved problems
        selected_index = complaint_listbox.curselection()
        if selected_index:
            complaint = complaint_listbox.get(selected_index)
            transfer_to_solved(complaint)
            messagebox.showinfo("Success", "Complaint transferred to solved problems.")
            complaint_listbox.delete(selected_index)
        else:
            messagebox.showerror("Error", "Please select a complaint.")

    transfer_button = tk.Button(admin_window, text="Transfer to Solved", command=transfer_complaint, font=("Helvetica", 16))
    transfer_button.place(x=800,y=600)
    #delete_button = tk.Button(admin_window, text="Delete", command=delete_complaint, font=("Helvetica", 16), bg='white')
    #delete_button.place(x=800,y=600)

    # Intercept close event to handle withdrawing the root window
    def on_close():
        root.deiconify()
        admin_window.destroy()

    admin_window.protocol("WM_DELETE_WINDOW", on_close)


def show_user_page():
    def validate_login(username, password, role):
        conn = sqlite3.connect('complaints.db')
        c = conn.cursor()
        # Check if the entered credentials exist in the users table
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        return user
    
    def update_password_in_database(username, new_password):
        # Function to update password in the database
        conn = sqlite3.connect('complaints.db')
        c = conn.cursor()
        c.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
        conn.commit()
        conn.close()

    user_window = tk.Toplevel(root)
    user_window.iconbitmap(r"C:\Users\manju\OneDrive\Desktop\wise\free-book-1210-450385.ico")
    user_window.title("Complaint Page")
    user_window.geometry("3000x1000")

    # Load background image
    user_background = Image.open(r"C:\Users\manju\OneDrive\Desktop\wise\user.jpg")
    user_background = user_background.resize((1500, 1000))  # Resize image to fit window
    user_background_photo = ImageTk.PhotoImage(user_background)

    # Create a label with the background image
    background_label = tk.Label(user_window, image=user_background_photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)

    # Ensure the image is not garbage collected
    background_label.image = user_background_photo

    def on_close():
        root.deiconify()
        user_window.destroy()
    user_window.protocol("WM_DELETE_WINDOW", on_close)

    def open_change_password_page():
        user_window.withdraw()  # Hide user page
        change_password_page(user_window, validate_login, update_password_in_database, "User")

    change_password_button = tk.Button(user_window, text="Change Password", command=open_change_password_page, font=("Helvetica", 14), bg='white')
    change_password_button.place(x=800, y=100)

    name_label = tk.Label(user_window, text="Person Name:", font=("Helvetica", 20), bg='#efffff')
    name_label.place(x=800, y=150)
    name_entry = tk.Entry(user_window, font=("Helvetica", 20))
    name_entry.place(x=1000, y=150)
    gender_label = tk.Label(user_window, text="Gender:", font=("Helvetica", 20), bg='#efffff')
    gender_label.place(x=800, y=250)
    gender_var = tk.StringVar(value="Female")
    male_radio = tk.Radiobutton(user_window, text="Male", variable=gender_var, value="Male", font=("Helvetica", 20), bg='#efffff')
    male_radio.place(x=1000, y=250)
    female_radio = tk.Radiobutton(user_window, text="Female", variable=gender_var, value="Female", font=("Helvetica", 20), bg='#efffff')
    female_radio.place(x=1200, y=250)
    college_label = tk.Label(user_window, text="Select College/Hostel Block:", font=("Helvetica", 20), bg='#efffff')
    college_label.place(x=800, y=350)
    college_var = tk.StringVar(value="Hostel A")
    college_dropdown = tk.OptionMenu(user_window, college_var, "Hostel A", "Hostel B", "Hostel C", "Hostel D", "College A", "College B", "College C", "College D")
    college_dropdown.place(x=1200, y=350)
    Room_label = tk.Label(user_window, text="Room No:", font=("Helvetica", 20), bg='#efffff')
    Room_label.place(x=800, y=450) 
    Room_entry = tk.Entry(user_window, font=("Helvetica", 20))
    Room_entry.place(x=1000, y=450)
    complaint_label = tk.Label(user_window, text="Complaint:", font=("Helvetica", 20), bg='#efffff')
    complaint_label.place(x=800, y=550)
    complaint_entry = tk.Entry(user_window, font=("Helvetica", 20))
    complaint_entry.place(x=1000, y=550)

    def submit_complaint():
        user_name = name_entry.get()
        user_gender = gender_var.get()
        user_complaint = complaint_entry.get()
        college_name = college_var.get()
        room_number = Room_entry.get()
        if not (user_name and user_gender and user_complaint and college_name and room_number):
            messagebox.showerror("Error", "Please fill in all the fields.")
            return

        # Insert complaint into the database
        conn = sqlite3.connect('complaints.db')
        c = conn.cursor()
        c.execute("INSERT INTO complaints (user_id, complaint) VALUES (?, ?)", (1, f"{user_name} ({user_gender}) ({college_name}) ({room_number}): {user_complaint}"))
        conn.commit()
        conn.close()

        # Clear entry fields
        name_entry.delete(0, tk.END)
        Room_entry.delete(0, tk.END)
        complaint_entry.delete(0, tk.END)

        # Display confirmation message
        messagebox.showinfo("Response Submitted", "Your response is submitted")

    submit_button = tk.Button(user_window, text="Submit", command=submit_complaint, font=("Helvetica", 14), bg='white')
    submit_button.place(x=1050, y=650)
def validate_login(username, password, role):
    conn = sqlite3.connect('complaints.db')
    c = conn.cursor()

    if role == "User":
        # Check if the entered credentials exist in the users table
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        return user
    elif role == "Admin":
        # Check if the entered credentials exist in the admins table
        c.execute("SELECT * FROM admins WHERE username=? AND password=?", (username, password))
        admin = c.fetchone()
        conn.close()
        return admin
    else:
        conn.close()
        return None

def on_login():
    username = username_entry.get()
    password = password_entry.get()
    role = role_var.get()
    if role:
        if role == "User":
            user = validate_login(username, password, role)
            if user:
                messagebox.showinfo("Login Successful", f"Welcome, {username}!")
                show_user_page()
                root.withdraw()  
                username_entry.delete(0, tk.END)  
                password_entry.delete(0, tk.END)  
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")
        elif role == "Admin":
            admin = validate_login(username, password, role)
            if admin:
                messagebox.showinfo("Login Successful", f"Welcome, {username}!")
                show_admin_page()
                root.withdraw()  
                username_entry.delete(0, tk.END)  
                password_entry.delete(0, tk.END)  
            else:
                messagebox.showerror("Login Failed", "Invalid username or password")
    else:
        messagebox.showerror("Role Selection", "Please select a role")

root = tk.Tk()
root.iconbitmap(r"C:\Users\manju\OneDrive\Desktop\wise\free-book-1210-450385.ico")
background_image = Image.open(r"C:\Users\manju\OneDrive\Desktop\wise\LOGIN.jpg")
root.title("Complaint Registration System")
background_image = background_image.resize((root.winfo_screenwidth(), root.winfo_screenheight()))
background_photo = ImageTk.PhotoImage(background_image)
canvas = tk.Canvas(root, width=root.winfo_screenwidth(), height=root.winfo_screenheight())
canvas.pack(fill="both", expand=True)
canvas.create_image(0, 0, anchor="nw", image=background_photo)

root.geometry("3000x1000")
role_var = tk.StringVar(value="User")
role_label = tk.Label(root, text="Select Role:", font=("Helvetica", 20), bg='#caeefe')
role_label.place(x=900, y=300)
user_radio = tk.Radiobutton(root, text="User", variable=role_var, value="User", font=("Helvetica", 20), bg='#caeefe')
user_radio.place(x=1100, y=300)
admin_radio = tk.Radiobutton(root, text="Admin", variable=role_var, value="Admin", font=("Helvetica", 20), bg='#caeefe')
admin_radio.place(x=1250, y=300)

username_label = tk.Label(root, text="Username:", font=("Helvetica", 20), bg='#caeefe')
username_label.place(x=900, y=400)
username_entry = tk.Entry(root, font=("Helvetica", 20))
username_entry.place(x=1100, y=400)

password_label = tk.Label(root, text="Password:", font=("Helvetica", 20), bg='#caeefe')
password_label.place(x=900, y=450)
password_entry = tk.Entry(root, show="*", font=("Helvetica", 20))
password_entry.place(x=1100, y=450)

login_button = tk.Button(root, text="Login", command=on_login, font=("Helvetica", 20), bg='white')
login_button.place(x=1250, y=550)

root.mainloop()
