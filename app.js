import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

const app = express();
const SERVER_PORT = 3019;

// Secret Key는 아래처럼 평문으로 작성X, 외부에 노출되면 안되기 때문에 .env로 관리
const ACCESS_TOKEN_SECRET_KEY = 'Mario'; // Access Token Secret Key 정의
const REFRESH_TOKEN_SECRET_KEY = 'Luigi'; // Refresh Token Secret Key 정의

app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
    return res.status(200).send('Hello Token!');
});

const tokenStorages = {}; // Refresh Token을 관리할 객체

/** Access Token, Refresh Token 발급 API **/
app.post('/tokens', async (req, res) => {
    // id 전달
    const { id } = req.body;

    // Access Token과 Refresh Token을 발급
    const accessToken = jwt.sign({ id: id }, ACCESS_TOKEN_SECRET_KEY, { expiresIn: '10s' });
    const refreshToken = jwt.sign({ id: id }, REFRESH_TOKEN_SECRET_KEY, { expiresIn: '7d' });

    tokenStorages[refreshToken] = {
        id: id,
        ip: req.ip,
        userAgent: req.headers['user-agent'], // 어떤 방식으로 요청했는지 ex) Firefox, Chrome, Mobile 등등
    };

    // Token 발급 후, Token Storages에 어떻게 저장되는지 확인
    console.log(tokenStorages);

    // Client에게 Cookie(Token)을 할당
    res.cookie('accessToken', accessToken);
    res.cookie('refreshToken', refreshToken);

    return res.status(200).json({ message: 'Token이 정상적으로 발급되었습니다.' });
});

app.listen(SERVER_PORT, () => {
    console.log(SERVER_PORT, '포트로 서버가 열렸습니다.');
});
