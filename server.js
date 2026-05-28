const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');
require('dotenv').config();

if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    console.error("XATO: .env faylida GOOGLE_CLIENT_ID yoki GOOGLE_CLIENT_SECRET topilmadi!");
    process.exit(1);
}

// CORS sozlamalari - Frontend backend bilan gaplashishi uchun
fastify.register(cors, { 
    origin: true,
    credentials: true
});

const PORT = 3000;

fastify.get('/health', async () => {
    return { status: 'ok' };
});

fastify.listen({ port: PORT, host: '0.0.0.0' }, (err) => {
    if (err) throw err;
    console.log(`Backend server http://localhost:${PORT} da muvaffaqiyatli ishga tushdi`);
});