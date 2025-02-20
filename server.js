const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const fs = require('fs');

require("dotenv").config();

const app = express();
const PORT = 3000;

// 🔐 Твой секретный ключ (из настроек CyberSource)
const SECRET_KEY = process.env.secret_key;
// Middleware для обработки JSON
app.use(bodyParser.json());

// 📌 Проверка подписи от CyberSource
function verifySignature(req) {
    const signatureHeader = req.headers['x-cybersource-signature'];
    if (!signatureHeader) return false;

    const requestBody = JSON.stringify(req.body);
    const computedSignature = crypto
        .createHmac('sha256', SECRET_KEY)
        .update(requestBody)
        .digest('base64');

    return computedSignature === signatureHeader;
}

// 📌 Формирование подписанного ответа
function generateSignature(responseBody) {
    return crypto
        .createHmac('sha256', SECRET_KEY)
        .update(responseBody)
        .digest('base64');
}

// 📌 Health Check (для CyberSource)
app.get('/health-check', (req, res) => {
    res.status(200).send('Webhook is healthy');
});

// 📌 Webhook (обработка уведомлений от CyberSource)
app.post('/cybersource-webhook', (req, res) => {
    console.log('🔹 Входящий вебхук:', req.body);

    // 1️⃣ Проверяем подпись
    if (!verifySignature(req)) {
        console.error('⛔ Неверная подпись!');
        return res.status(401).json({ error: 'Invalid signature' });
    }

    // 2️⃣ Логируем данные
    const timestamp = new Date().toISOString();
    const logData = `[${timestamp}] ${JSON.stringify(req.body, null, 2)}\n\n`;
    fs.appendFile('cybersource_webhook.log', logData, (err) => {
        if (err) console.error('Ошибка записи в лог:', err);
    });

    // 3️⃣ Формируем ответ и подписываем его
    const responseBody = JSON.stringify({ message: 'Webhook received' });
    const signature = generateSignature(responseBody);

    // 4️⃣ Отправляем ответ CyberSource
    res.setHeader('x-cybersource-signature', signature);
    res.status(200).json({ message: 'Webhook received' });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`🚀 Сервер слушает вебхуки на http://localhost:${PORT}`);
});
