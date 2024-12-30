Şifre Yöneticisi

Bu proje, kullanıcıların şifrelerini güvenli bir şekilde saklamalarını sağlayan basit bir şifre yöneticisi uygulamasıdır.


Özellikler:

Şifreler AES algoritması ile şifrelenir.

Şifreleme anahtarı, kullanıcı tarafından yüklenen bir görselden elde edilir.

Kullanıcı dostu bir arayüz ile şifre ekleme, görüntüleme ve çözme işlemleri kolaylıkla yapılabilir.

Her kullanıcı, sadece kendi şifrelerine erişebilir. Diğer kullanıcılar, başkalarının şifrelerini göremez.

Kullanılan Teknolojiler:
Python

OpenCV (görüntü işleme)

Tkinter (arayüz tasarımı)

SQLite (veritabanı)

PyCryptodome (şifreleme)


Kurulum:


Proje dosyalarını indirin.

Gerekli kütüphaneleri yükleyin:
pip install opencv-python pycryptodome tkinter

main.py dosyasını çalıştırın.

Kullanım:

Uygulamayı ilk kez çalıştırdığınızda, bir master ID ve master key belirleyerek kayıt olmanız gerekir.

Kayıt olduktan sonra, master ID ve master key ile giriş yapabilirsiniz.

Giriş yaptıktan sonra, "Şifre Ekle" butonuna tıklayarak yeni şifreler ekleyebilirsiniz.

Şifre eklerken, şifrelenecek web sitesini, kullanıcı adını ve şifreyi girin. Ayrıca, şifreleme anahtarı olarak kullanılacak bir görsel seçin.

"Şifreleri Görüntüle" butonuna tıklayarak kaydedilen şifreleri tablo şeklinde görüntüleyebilirsiniz.

Şifreyi çözmek için, ilgili satırı seçin ve "Şifreyi Göster" butonuna tıklayın. Şifreleme anahtarı olarak kullanılan görseli seçmeniz istenecektir.

"Çıkış Yap" butonuna tıklayarak oturumunuzu kapatabilirsiniz.


Güvenlik:

Şifreler, AES algoritması ile güvenli bir şekilde şifrelenir.

Şifreleme anahtarı, kullanıcı tarafından yüklenen bir görselden elde edilir ve veritabanında saklanmaz.

Her kullanıcı, sadece kendi şifrelerine erişebilir.

Lisans:

Bu proje MIT Lisansı altında lisanslanmıştır.

Geliştirici:

Bu proje, cncresul tarafından geliştirilmiştir.

