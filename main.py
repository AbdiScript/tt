import time
import multiprocessing
import random
import os
import requests
from datetime import datetime
from bitcoin import encode_pubkey, privtopub
from Crypto.Hash import SHA256, RIPEMD160

# اطلاعات ربات تلگرام
TELEGRAM_TOKEN = "7306877915:AAHR-EDl87kj1eiLVWUxyiHnaQoiJUTW8Fc"
CHAT_ID = "567639577"

# تابع ارسال پیام به تلگرام
def send_telegram_message(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, data=data)
    except Exception as e:
        # Add SMS Backup way!!!!!!
        print(f"Error sending message to Telegram: {e}")

# تابع تبدیل به hash160 (Public Key Hash)
def pubkey_to_hash160(pubkey):
    # محاسبه SHA-256
    sha256_hash = SHA256.new(bytes.fromhex(pubkey)).digest()

    # محاسبه RIPEMD-160
    ripemd160 = RIPEMD160.new(sha256_hash).digest()

    return ripemd160.hex()

# تابع برای بررسی تطابق هش کلید عمومی
def check_hash_match(N, M, target_hash, found_flag, checked_keys, max_checks):
    while not found_flag.value and checked_keys.value < max_checks:  # تا زمانی که نتیجه پیدا نشده است یا تعداد کلیدها کمتر از حد است
        # انتخاب تصادفی عدد در بازه N تا M
        random_key = random.randint(M, N)

        # تبدیل عدد به هگز 64 کاراکتری
        hex_key = format(random_key, '064x')

        # تولید کلید عمومی فشرده از روی کلید خصوصی
        pubkey = privtopub(hex_key)
        compressed_pubkey = encode_pubkey(pubkey, 'hex_compressed')

        # محاسبه Hash 160 کلید عمومی
        hash160 = pubkey_to_hash160(compressed_pubkey)

        # بررسی تطابق با Z
        if hash160 == target_hash:
            found_flag.value = 1
            with open("found.txt", "w") as f:
                f.write(f"Found matching key: {hex_key} (Random Key: {random_key})\n")
            print(f"Found matching key: {hex_key} (Random Key: {random_key})")

            # ارسال پیام به تلگرام برای مطلع کردن از پیدا شدن
            send_telegram_message(f"❌❌❌ *Matching key found:* ❌❌❌\n`{hex_key}`\n🟢 Random Key: *{random_key}*")

        # افزایش تعداد کلیدهای بررسی شده
        with checked_keys.get_lock():
            checked_keys.value += 1

# تابع برای پرینت تعداد کلیدهای بررسی شده هر 10 دقیقه
def print_progress(checked_keys, found_flag):
    while not found_flag.value:  # ادامه چاپ تا زمانی که نتیجه پیدا شود
        time.sleep(600)  # 600 ثانیه معادل 10 دقیقه
        with checked_keys.get_lock():
            current_time = datetime.now().strftime("%Y/%m/%d %H:%M")
            print(f"{current_time} - Total checked keys so far: {checked_keys.value}")

# تابع اصلی برای مدیریت چندپردازشی
def run_search(N, M, Z, num_processes, max_checks):
    target_hash = Z
    found_flag = multiprocessing.Value('i', 0)  # Flag برای متوقف کردن دیگر پروسه‌ها در صورت یافتن نتیجه
    checked_keys = multiprocessing.Value('i', 0)  # شمارنده تعداد کلیدهای بررسی شده

    # ایجاد فرآیندهای موازی
    processes = []
    start_time = time.time()

    # ایجاد پردازش‌ها برای جستجو
    for i in range(num_processes):
        p = multiprocessing.Process(target=check_hash_match, args=(N, M, target_hash, found_flag, checked_keys, max_checks))
        processes.append(p)
        p.start()

    # ایجاد پردازش نظارت برای چاپ تعداد کلیدهای بررسی شده
    monitor_process = multiprocessing.Process(target=print_progress, args=(checked_keys, found_flag))
    monitor_process.start()

    # مانیتور کردن وضعیت و توقف فرآیندها بعد از یافتن نتیجه یا رسیدن به حد مجاز
    while not found_flag.value and checked_keys.value < max_checks:
        time.sleep(1)  # تا زمانی که کلید پیدا نشده است یا محدودیت چک نشده، هر 1 ثانیه چک کن

    # وقتی کلید پیدا شد یا تعداد کلیدهای چک شده به حداکثر رسید، تمام فرآیندها را متوقف کن
    for p in processes:
        p.terminate()
        p.join()

    monitor_process.terminate()
    monitor_process.join()

    total_time = time.time() - start_time
    print(f"Total time: {total_time:.2f} seconds.")

    # ارسال پیام به تلگرام بعد از اتمام عملیات
    send_telegram_message(f"✳️ Process completed.\n🟡 Total checked keys: *{checked_keys.value}*\n🔴 Total time: *{total_time:.2f}* seconds\n🟢 Used cores: *{num_processes}*")

# ورودی‌ها
if __name__ == "__main__":
    N = 147573952589676412927
    M = 73786976294838206464
    Z = "739437bb3dd6d1983e66629c5f08c70e52769371"

    # تعداد پردازنده‌های موجود
    num_processes = multiprocessing.cpu_count()
    max_checks = 10000

    print(f"Using {num_processes} CPU cores.")

    run_search(N, M, Z, num_processes, max_checks)
