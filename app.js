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
    const accessToken = createAccessToken(id); // jwt.sign({ id: id }, ACCESS_TOKEN_SECRET_KEY, { expiresIn: '10s' });
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

/** Access Token을 Validate하는 API **/
app.get('/tokens/validate', async (req, res) => {
    const { accessToken } = req.cookies;

    // Access Token이 존재하는지 확인
    if (!accessToken) {
        return res.status(400).json({ errorMessage: 'Access Token이 존재하지 않습니다.' });
    }

    const payload = validateToken(accessToken, ACCESS_TOKEN_SECRET_KEY);

    if (!payload) {
        return res.status(401).json({ errorMessage: 'Access Token이 유효하지 않습니다.' });
    }

    const { id } = payload;
    return res.status(200).json({ message: `${id}의 Payload를 가진 Token이 정상적으로 인증되었습니다.` });
});

// Token을 validate하고, Payload를 조회하기 위한 함수
function validateToken(token, secretKey) {
    // 성공하면 payload, 실패하면 null 반환
    try {
        return jwt.verify(token, secretKey);
    } catch (err) {
        return null;
    }
}

function createAccessToken(id) {
    return jwt.sign({ id }, ACCESS_TOKEN_SECRET_KEY, { expiresIn: '10s' });
}

/** Refresh Token을 이용해서, Access Token을 재발급하는 API  */
app.post('/tokens/refresh', async (req, res) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        return res.status(400).json({ errorMessage: 'Refresh Token이 존재하지 않습니다.' });
    }

    const payload = validateToken(refreshToken, REFRESH_TOKEN_SECRET_KEY);

    if (!payload) {
        return res.status(401).json({ errorMessage: 'Refresh Token이 정상적이지 않습니다.' });
    }

    const userInfo = tokenStorages[refreshToken];

    if (!userInfo) {
        return res.status(419).json({ errorMessage: 'Refresh Token의 정보가 서버에 존재하지 않습니다.' });
    }

    const newAccessToken = createAccessToken(userInfo.id); // 이전 code: const newAccessToken = jwt.sign(userInfo.id, ACCESS_TOKEN_SECRET_KEY);

    res.cookie('accessToken', newAccessToken);
    return res.status(200).json({ message: 'Access Token을 정상적으로 새롭게 발급했습니다.' });
});

app.listen(SERVER_PORT, () => {
    console.log(SERVER_PORT, '포트로 서버가 열렸습니다.');
});
