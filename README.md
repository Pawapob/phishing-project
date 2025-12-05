วิธีรันโปรเจ็กต์
1) ติดตั้ง Dependencies
จำเป็นต้องมี Python 3.9+

1.ติดตั้ง dependencies:
pip install -r requirements.txt

2.)วิธีรัน API (Backend)

1.ในTerminal พิมพ์:
Cd phishing-api

2.เริ่มเซิร์ฟเวอร์ FastAPI ด้วย uvicorn:
uvicorn app:app --reload

2.1 เปิดดูผลได้ที่:
http://127.0.0.1:8000

2.1.1 ดู API แบบ Swagger UI:
http://127.0.0.1:8000/docs

3.)วิธีรันเว็บ (Frontend)

1.ในTerminal พิมพ์:
Cd phishing-frontend

2.เปิดเว็บ พิมพ์:
npm run dev

3.เข้าตามลิ้งที่มันให้มาตามตัวอย่างข้างล่าง:
  ➜  Local:   http://localhost:xxxx/

4.นำไปพิมพ์ในเบราว์เซอร์
  

