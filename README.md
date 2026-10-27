# Laporan E02 Keamanan Informasi: Key Distribution (KDC) dan Komunikasi AES
 
**Anggota kelompok**
- Shafira Nauraishma Zahida   (5025241235)
- Najma Lail Arazy            (5025241243)
## 1. Latar Belakang dan Tujuan
 
Tugas ini meminta kami membuat simulasi distribusi kunci simetris dengan bantuan Key Distribution Center (KDC). Ada tiga entitas, yaitu KDC, Alice, dan Bob, yang masing-masing berjalan di perangkat dengan IP address berbeda. Alice dan Bob tidak pernah berbagi kunci sebelumnya. Mereka hanya punya master key masing-masing yang dibagi dengan KDC. Dari situ KDC membuatkan session key yang dipakai Alice dan Bob untuk berkomunikasi dengan AES.
 
Ketentuan yang kami penuhi:
- AES dan KDC ditulis sendiri, tanpa library kriptografi. Library yang dipakai hanya `socket`, `threading`, `secrets`, dan `os`.
- Key dan plaintext berformat ASCII, ciphertext ditampilkan dalam hex.
- Key tidak di-hardcode. Key dimasukkan saat program dijalankan dan bisa diganti tanpa restart.
- Alice dan Bob bisa mengirim dan menerima pesan (dua arah).
- Transmisi data dapat diamati lewat Wireshark.
## 2. Arsitektur
 
```
            +-----------+
            |    KDC    |   Ka (dengan Alice), Kb (dengan Bob)
            +-----------+
             ^         |
     langkah 1|         |langkah 2
             |         v
        +---------+  langkah 3, 4, 5  +---------+
        |  Alice  | <---------------> |   Bob   |
        +---------+   chat AES (Ks)   +---------+
```
 
- Semua komunikasi memakai TCP socket.
- KDC menerima koneksi dari Alice (langkah 1 dan 2).
- Bob menunggu koneksi dari Alice. Langkah 3 sampai 5 dan seluruh chat lewat satu koneksi TCP yang sama.
- Di sisi Alice dan Bob ada satu thread khusus untuk menerima pesan, sementara thread utama membaca input keyboard untuk mengirim. Karena itu keduanya bisa menjadi sender sekaligus receiver.
### Struktur file
 
| File | Fungsi |
|---|---|
| `aes.py` | Implementasi AES-128/192/256 manual, mode CBC dan ECB, padding PKCS#7. Menjalankan `python aes.py` akan menguji hasil dengan vektor uji FIPS-197 |
| `common.py` | Fungsi bantu: konversi ASCII dan hex (`enc()`, `dec()`), pembuatan nonce, fungsi `f(N2)`, dan log |
| `kdc.py` | Program KDC: menyimpan master key, membuat session key, membalas langkah 2 |
| `peer.py` | Logika bersama Alice dan Bob: langkah 3 sampai 5, thread penerima, kirim dan terima chat |
| `alice.py`, `bob.py` | Program utama untuk masing-masing entitas |
 
## 3. Skenario Distribusi Kunci
 
Notasi: `Ka` dan `Kb` adalah master key Alice dan Bob yang dibagi dengan KDC, `Ks` adalah session key, `N1` dan `N2` adalah nonce, `E(K, X)` adalah enkripsi X dengan kunci K.
 
```
1. Alice -> KDC   : ID_A || ID_B || N1
2. KDC   -> Alice : E(Ka, [Ks || ID_B || N1]) || E(Kb, [Ks || ID_A])
3. Alice -> Bob   : E(Kb, [Ks || ID_A])
4. Bob   -> Alice : E(Ks, N2)
5. Alice -> Bob   : E(Ks, f(N2))
```
 
Penjelasan tiap langkah:
 
1. Alice meminta session key untuk berkomunikasi dengan Bob. Permintaan ini berisi identitas kedua pihak dan nonce `N1`. Langkah ini dikirim sebagai teks biasa karena tidak ada rahasia di dalamnya.
2. KDC membuat `Ks` secara acak, lalu membungkusnya dua kali. Bagian pertama dienkripsi dengan `Ka` sehingga hanya Alice yang bisa membukanya. Bagian kedua adalah "tiket" untuk Bob yang dienkripsi dengan `Kb`. Alice tidak punya `Kb`, jadi dia tidak bisa membaca tiket itu dan hanya meneruskannya.
3. Alice mengirim tiket tersebut ke Bob. Bob membukanya dengan `Kb` dan mendapatkan `Ks` beserta identitas Alice.
4. Bob membuat nonce `N2` dan mengirimkannya ke Alice dengan enkripsi `Ks`.
5. Alice mendekripsi `N2`, menerapkan fungsi `f`, lalu mengirim `f(N2)` dengan enkripsi `Ks`. Bob memeriksa hasilnya. Jika cocok, Bob yakin lawan bicaranya memegang `Ks` yang benar.
Setelah langkah 5, kedua pihak saling mengirim pesan dengan format `MSG|<hex>`, di mana isinya adalah plaintext yang dienkripsi AES dengan `Ks`.
 
Catatan implementasi:
- Di jaringan, langkah 2 dikirim sebagai `STEP2|<hex E(Ka,..)>|<hex E(Kb,..)>`. Langkah lainnya memakai format serupa (`STEP1|...`, `STEP3|<hex>`, `STEP4|<hex>`, `STEP5|<hex>`).
- Alice memeriksa bahwa `N1` dan `ID_B` pada balasan KDC sama dengan yang dia kirim. Pemeriksaan ini mencegah balasan lama (replay) diterima.
- Skenario tidak menentukan bentuk `f`, jadi kami memakai `f(N) = N - 1`. Fungsi ini bisa diubah di `common.f()`.
## 4. Implementasi AES
 
AES ditulis manual di `aes.py` dan mendukung key 128, 192, dan 256 bit (16, 24, atau 32 karakter ASCII).
 
- **S-Box** dihitung sendiri: invers perkalian di GF(2^8) lalu transformasi affine. Tidak ada tabel yang ditempel.
- **Key Expansion** menghasilkan round key untuk 10, 12, atau 14 round sesuai panjang key.
- **Tiap round** terdiri dari SubBytes, ShiftRows, MixColumns, dan AddRoundKey. Round terakhir tidak memakai MixColumns. Blok 16 byte diperlakukan sebagai matriks 4x4.
- **Mode CBC** dipakai secara default. Tiap blok di-XOR dengan ciphertext blok sebelumnya, dan blok pertama memakai IV acak 16 byte yang ditaruh di depan ciphertext. Akibatnya plaintext yang sama menghasilkan ciphertext berbeda setiap kali dikirim.
- **Mode ECB** tersedia sebagai pembanding. Ubah `MODE = "ECB"` di `common.py` (harus sama di semua perangkat).
- **Padding PKCS#7** dipakai supaya panjang data kelipatan 16 byte. Padding yang tidak valid saat dekripsi dianggap sebagai tanda key salah.
- Hasil implementasi diuji dengan vektor uji FIPS-197 lewat `python aes.py`.
## 5. Implementasi KDC
 
`kdc.py` menyimpan master key `Ka` dan `Kb` di memori. Key ini diminta saat program dimulai, tidak ditulis di dalam kode. Saat menerima permintaan langkah 1, KDC membuat `Ks` acak 16 karakter dengan modul `secrets`, lalu menyusun balasan langkah 2 dengan AES buatan sendiri.
 
## 6. Cara Menjalankan
 
Contoh pembagian perangkat: KDC `192.168.1.10`, Alice `192.168.1.20`, Bob `192.168.1.30`. Sesuaikan dengan IP masing-masing perangkat (cek dengan `ipconfig`). Ketiga perangkat harus berada di jaringan yang sama dan saling bisa `ping`. Port yang dipakai di sini 6000 (KDC) dan 6001 (Bob), dan firewall harus mengizinkannya.
 
Hanya butuh Python 3, tidak ada library yang perlu diinstal.
 
Urutan menjalankan: KDC, lalu Bob, lalu Alice.
 
```
# Perangkat KDC
python kdc.py --port 6000
# Masukkan master key Alice (Ka) dan Bob (Kb), masing-masing 16/24/32 karakter ASCII
 
# Perangkat Bob
python bob.py --port 6001
# Masukkan Kb, harus sama dengan Kb di KDC
 
# Perangkat Alice
python alice.py --kdc-ip 192.168.1.10 --kdc-port 6000 --bob-ip 192.168.1.30 --bob-port 6001
# Masukkan Ka, harus sama dengan Ka di KDC
```
 
Langkah 1 sampai 5 berjalan otomatis. Setelah muncul `** Kanal aman siap **`, ketik teks di Alice atau Bob untuk saling kirim pesan.
 
Untuk uji coba di satu laptop, jalankan tiga terminal dengan `127.0.0.1`. Pengujian untuk demo tetap memakai tiga IP berbeda.
 
### Perintah interaktif
 
Key bisa diubah tanpa menjalankan ulang program.
 
| Di mana | Perintah | Fungsi |
|---|---|---|
| Alice / Bob | `/key <key>` | Ganti master key sendiri (lalu samakan di KDC) |
| Alice | `/rekey` | Ulangi langkah 1 sampai 5 untuk mendapat Ks baru |
| Alice / Bob | `/status` | Lihat key, Ks, dan status kanal |
| KDC | `/setkey <id> <key>` | Ganti master key Alice atau Bob di KDC |
| KDC | `/nextks <16 char>` | Paksa Ks berikutnya (untuk test case tertentu) |
| KDC | `/keys` | Lihat master key yang terdaftar |
| Semua | `/quit` | Keluar |
 
## 7. Pengujian
 
| No | Skenario | Cara | Yang diamati |
|---|---|---|---|
| 1 | Self-test AES | `python aes.py` | Seluruh vektor FIPS-197 lolos |
| 2 | Distribusi kunci | Jalankan KDC, Bob, Alice | Langkah 1 sampai 5 selesai, muncul `Kanal aman siap` |
| 3 | Chat dua arah | Kirim pesan dari Alice lalu dari Bob | Pesan terdekripsi sama persis di penerima, ciphertext tampil dalam hex |
| 4 | Pesan yang sama dikirim dua kali | Kirim teks yang sama berulang | Ciphertext berbeda (IV acak pada CBC) |
| 5 | Variasi panjang pesan | Pesan pendek, tepat 16 karakter, lebih dari 32 karakter, berisi simbol | Semua terdekripsi benar (padding PKCS#7) |
| 6 | Ganti session key | `/rekey` di Alice | Ks berubah, chat tetap berjalan tanpa restart |
| 7 | Ganti master key | `/setkey Alice <key baru>` di KDC, `/key <key baru>` di Alice, lalu `/rekey` | Distribusi kunci berhasil dengan key baru |
| 8 | Key salah | Ka di Alice dibuat berbeda dengan KDC, lalu `/rekey` | Dekripsi langkah 2 gagal (padding tidak valid), program tidak crash |
| 9 | Tiga perangkat berbeda | Jalankan di tiga IP berbeda | Semua langkah dan chat berjalan antarperangkat |
 
## 8. Pengamatan dengan Wireshark
 
1. Pilih interface yang benar (Wi-Fi, Ethernet, atau adapter VM bridged). Jika semua program berjalan di satu laptop lewat `127.0.0.1`, di Windows gunakan *Npcap Loopback Adapter*. Saat demo kami memakai IP berbeda.
2. Mulai capture sebelum Alice dijalankan.
3. Display filter yang kami siapkan:
   - semua trafik tugas: `tcp.port == 6000 || tcp.port == 6001`
   - hanya KDC: `tcp.port == 6000`
   - hanya Alice dan Bob: `tcp.port == 6001`
   - per IP: `ip.addr == 192.168.1.10 || ip.addr == 192.168.1.20 || ip.addr == 192.168.1.30`
   - hanya paket yang berisi data: tambahkan `&& tcp.len > 0`
4. Klik kanan paket, pilih **Follow > TCP Stream**. Tiap langkah terlihat jelas karena formatnya teks, dan hex-nya bisa dicocokkan dengan log program.
Hasil pengamatan: langkah 1 terlihat sebagai plaintext (ID dan nonce), sedangkan langkah 2 sampai 5 dan semua `MSG` berupa ciphertext hex yang tidak bisa dibaca tanpa key.
 
 
## 9. Pembagian Kontribusi
 
| Anggota | Kontribusi |
|---|---|
| Shafira Nauraishma Zahida | `aes.py`, `common.py`, `README.md`, dan pengujian bersama |
| Najma Lail Arazy | `alice.py`, `bob.py`, `kdc.py`, `peer.py`, dan pengujian bersama |
 
## 10. Catatan dan Keterbatasan
 
- Master key disimpan di memori selama program berjalan dan tidak disimpan ke file.
- Fungsi `f(N) = N - 1` dipilih sederhana karena skenario tidak menentukan bentuknya.
- Komunikasi memakai TCP tanpa autentikasi tambahan di luar skenario lima langkah.
