import psycopg2
from decouple import config

try:
    connection = psycopg2.connect(
        dbname=config('DB_NAME'),
        user=config('DB_USER'),
        password=config('DB_PASS'),
        host=config('DB_HOST'),
        port=config('DB_PORT'),
    )
    print("Ulanish muvaffaqiyatli!")
    connection.close()
except Exception as e:
    print(f"Xatolik: {e}")
