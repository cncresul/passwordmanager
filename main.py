# main.py
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import sqlite3
from image_processing import extract_features
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64

# utils klasörünün tam yolunu bulun
utils_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils')

# utils klasörünü Python'un modül arama yoluna ekleyin
sys.path.insert(0, utils_path)

current_user_id = None  # Kullanıcı ID'sini global olarak tanımla

def generate_key(image_path):
    """
    Görüntüden şifreleme anahtarı üretir.

    Args:
        image_path (str): Görüntü dosyasının yolu.

    Returns:
        bytes: Şifreleme anahtarı.
    """
    features = extract_features(image_path)
    hash = SHA256.new(features.tobytes())
    key = hash.digest()
    return key


def encrypt_password(password, key):
    """
    Şifreyi şifreler.

    Args:
        password (str): Şifre.
        key (bytes): Şifreleme anahtarı.

    Returns:
        str: Şifrelenmiş şifre.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    encrypted_password = base64.b64encode(
        cipher.nonce + tag + ciphertext).decode()
    return encrypted_password


def decrypt_password(encrypted_password, key):
    """
    Şifreyi çözer.

    Args:
        encrypted_password (str): Şifrelenmiş şifre.
        key (bytes): Şifreleme anahtarı.

    Returns:
        str: Çözülmüş şifre.
    """
    try:
        encrypted_password = base64.b64decode(encrypted_password)
        nonce = encrypted_password[:AES.block_size]
        tag = encrypted_password[AES.block_size:AES.block_size * 2]
        ciphertext = encrypted_password[AES.block_size * 2:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_password = cipher.decrypt_and_verify(ciphertext,
                                                       tag).decode()
        return decrypted_password
    except (ValueError, KeyError):
        return "Şifre çözme hatası!"


def browse_image():
    """
    Kullanıcının bir görüntü dosyası seçmesini sağlar.
    """
    filename = filedialog.askopenfilename(
        initialdir="/",
        title="Görüntü Seç",
        filetypes=(("Image files", "*.jpg *.jpeg *.png *.bmp"), ("all files",
                                                                "*.*")))
    image_path_entry.delete(0, tk.END)
    image_path_entry.insert(0, filename)


def add_password():
    """
    Yeni bir şifre ekler.
    """
    global current_user_id
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    image_path = image_path_entry.get()

    if not all([website, username, password, image_path]):
        messagebox.showerror("Hata", "Lütfen tüm alanları doldurun.")
        return

    try:
        key = generate_key(image_path)
        encrypted_password = encrypt_password(password, key)

        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO passwords (website, username, password, user_id) VALUES (?, ?, ?, ?)",
            (website, username, encrypted_password, current_user_id))
        conn.commit()
        conn.close()

        messagebox.showinfo("Başarılı", "Şifre başarıyla eklendi.")
        clear_entries()
    except Exception as e:
        messagebox.showerror("Hata", f"Şifre eklenirken bir hata oluştu: {e}")


def view_passwords():
    """
    Kaydedilen şifreleri tablo şeklinde görüntüler ve şifreyi göstermek için buton kullanır.
    """
    global current_user_id
    try:
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM passwords WHERE user_id=?",
                       (current_user_id,))
        passwords = cursor.fetchall()
        conn.close()

        if not passwords:
            messagebox.showinfo("Bilgi", "Henüz kaydedilmiş şifre yok.")
            return

        passwords_window = tk.Toplevel(window)
        passwords_window.title("Şifreler")
        passwords_window.configure(bg="#f0f0f0")

        # Tablo oluştur
        tree = ttk.Treeview(passwords_window, columns=("Website", "Username", "Şifre"), show="headings")
        tree.heading("Website", text="Website")
        tree.heading("Username", text="Kullanıcı Adı")
        tree.heading("Şifre", text="Şifre")

        # Şifreleri tabloya ekle (şifreleri gizlemeden)
        for password in passwords:
            tree.insert("", tk.END, values=(password[1], password[2], password[3]))  # Şifrelenmiş şifreyi göster

        tree.pack()

        # Şifreyi gösterme fonksiyonu
        def show_password():
            item = tree.selection()[0]
            encrypted_password = tree.item(item)['values'][2]  # Şifrelenmiş şifreyi al

            image_path = filedialog.askopenfilename(
                initialdir="/",
                title="Görüntü Seç",
                filetypes=(("Image files", "*.jpg *.jpeg *.png *.bmp"), ("all files",
                                                                        "*.*")))
            if not image_path:
                return

            try:
                key = generate_key(image_path)
                decrypted_password = decrypt_password(encrypted_password, key)
                messagebox.showinfo("Şifre", decrypted_password)  # Şifreyi messagebox ile göster
            except Exception as e:
                messagebox.showerror("Hata", f"Şifre çözülemedi: {e}")

        # Şifre göster butonu
        show_button = tk.Button(passwords_window, text="Şifreyi Göster", command=show_password, bg="#007bff", fg="white")
        show_button.pack(pady=10)

    except Exception as e:
        messagebox.showerror("Hata",
                             f"Şifreler alınırken bir hata oluştu: {e}")


def clear_entries():
    """
    Giriş alanlarını temizler.
    """
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    image_path_entry.delete(0, tk.END)


def create_database():
    """
    Veritabanını oluşturur.
    """
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY AUTOINCREMENT, website TEXT, username TEXT, password TEXT, user_id INTEGER)"""
    )
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, master_id TEXT, master_key TEXT)"""
    )
    conn.commit()
    conn.close()


def login():
    """
    Kullanıcının master ID ve master key ile giriş yapmasını sağlar.
    """
    global current_user_id
    master_id = master_id_entry.get()
    master_key = master_key_entry.get()

    if not all([master_id, master_key]):
        messagebox.showerror("Hata", "Lütfen tüm alanları doldurun.")
        return

    try:
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE master_id=? AND master_key=?",
                       (master_id, master_key))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Giriş başarılı
            current_user_id = user[0]
            login_window.destroy()
            show_main_window()
        else:
            messagebox.showerror("Hata", "Yanlış master ID veya master key.")
    except Exception as e:
        messagebox.showerror("Hata", f"Giriş yaparken bir hata oluştu: {e}")


def register():
    """
    Yeni bir kullanıcı kaydı oluşturur.
    """
    master_id = master_id_entry.get()
    master_key = master_key_entry.get()

    if not all([master_id, master_key]):
        messagebox.showerror("Hata", "Lütfen tüm alanları doldurun.")
        return

    try:
        conn = sqlite3.connect('passwords.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (master_id, master_key) VALUES (?, ?)",
                       (master_id, master_key))
        conn.commit()
        conn.close()

        messagebox.showinfo("Başarılı", "Kayıt başarıyla oluşturuldu.")
        login()
    except Exception as e:
        messagebox.showerror("Hata", f"Kayıt oluşturulurken bir hata oluştu: {e}")


def show_main_window():
    """
    Ana pencereyi gösterir.
    """
    global window, website_entry, username_entry, password_entry, image_path_entry
    # Ana pencereyi oluştur
    window = tk.Tk()
    window.title("Şifre Yöneticisi")
    window.configure(bg="#f0f0f0")  # Arka plan rengini ayarla

    # Etiketler ve giriş alanları
    website_label = tk.Label(window, text="Website:", bg="#f0f0f0", fg="#333333")
    website_label.grid(row=0, column=0, padx=10, pady=10)
    website_entry = tk.Entry(window, bg="white", bd=1, relief="solid")
    website_entry.grid(row=0, column=1, padx=10, pady=10)

    username_label = tk.Label(window, text="Kullanıcı Adı:", bg="#f0f0f0", fg="#333333")
    username_label.grid(row=1, column=0, padx=10, pady=10)
    username_entry = tk.Entry(window, bg="white", bd=1, relief="solid")
    username_entry.grid(row=1, column=1, padx=10, pady=10)

    password_label = tk.Label(window, text="Şifre:", bg="#f0f0f0", fg="#333333")
    password_label.grid(row=2, column=0, padx=10, pady=10)
    password_entry = tk.Entry(window, show="*", bg="white", bd=1, relief="solid")
    password_entry.grid(row=2, column=1, padx=10, pady=10)

    image_path_label = tk.Label(window, text="Görüntü Yolu:", bg="#f0f0f0", fg="#333333")
    image_path_label.grid(row=3, column=0, padx=10, pady=10)
    image_path_entry = tk.Entry(window, bg="white", bd=1, relief="solid")
    image_path_entry.grid(row=3, column=1, padx=10, pady=10)
    browse_button = tk.Button(window, text="Gözat", command=browse_image, bg="#007bff", fg="white")
    browse_button.grid(row=3, column=2, padx=10, pady=10)

    # Butonlar
    add_button = tk.Button(window, text="Şifre Ekle", command=add_password, bg="#28a745", fg="white")
    add_button.grid(row=4, column=0, columnspan=3, pady=10)

    view_button = tk.Button(window,
                            text="Şifreleri Görüntüle",
                            command=view_passwords, bg="#007bff", fg="white")
    view_button.grid(row=5, column=0, columnspan=3, pady=10)

    # Çıkış Yap butonu
    logout_button = tk.Button(window, text="Çıkış Yap", command=logout, bg="#dc3545", fg="white")
    logout_button.grid(row=6, column=0, columnspan=3, pady=10)  # Yeni bir satıra ekleyin

    window.mainloop()

def logout():
    """
    Kullanıcının oturumunu kapatır ve giriş ekranına geri döner.
    """
    global current_user_id
    current_user_id = None
    window.destroy()
    show_login_window()  # Giriş penceresini tekrar göster

def show_login_window():
    """
    Kullanıcı giriş penceresini oluşturur ve gösterir.
    """
    global login_window, master_id_entry, master_key_entry
    # Kullanıcı giriş penceresini oluştur
    login_window = tk.Tk()
    login_window.title("Giriş Yap")
    login_window.configure(bg="#f0f0f0")

    master_id_label = tk.Label(login_window, text="Kullanıcı Adı:", bg="#f0f0f0", fg="#333333")
    master_id_label.grid(row=0, column=0, padx=10, pady=10)
    master_id_entry = tk.Entry(login_window, bg="white", bd=1, relief="solid")
    master_id_entry.grid(row=0, column=1, padx=10, pady=10)

    master_key_label = tk.Label(login_window, text="Şifre:", bg="#f0f0f0", fg="#333333")
    master_key_label.grid(row=1, column=0, padx=10, pady=10)
    master_key_entry = tk.Entry(login_window, show="*", bg="white", bd=1, relief="solid")
    master_key_entry.grid(row=1, column=1, padx=10, pady=10)

    login_button = tk.Button(login_window, text="Giriş Yap", command=login, bg="#007bff", fg="white")
    login_button.grid(row=2, column=0, pady=10)

    register_button = tk.Button(login_window, text="Kayıt Ol", command=register, bg="#28a745", fg="white")
    register_button.grid(row=2, column=1, pady=10)

    login_window.mainloop()

# Veritabanını oluştur
create_database()

# Giriş penceresini göster
show_login_window()