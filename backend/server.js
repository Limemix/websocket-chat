const express = require('express');
const connectDB = require('./db')
const dotenv = require('dotenv');
const http = require('http');
const WebSocket = require('ws');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors')
const Message = require('./models/message');
const Group = require('./models/group');
const fs = require('fs');
const path = require('path');

const PORT = 3001;
dotenv.config()
connectDB();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });


// Налаштування сесій
const sessionParser = session({
    saveUninitialized: false,
    secret: 'bfd24471-1353-4026-baaf-77d5e4745499',
    resave: false,
});
app.use(cors({
    origin: 'http://localhost:3000', // Дозволяє запити тільки з цього домену
    credentials: true,
}));
app.use(sessionParser);

app.use(express.json()); // Для парсингу JSON у запитах

// Валідація імен користувачів та груп (НЕ ПІДТРИМУЄ КИРИЛИЦЮ)
const validateName = (name) => /^[a-zA-Z0-9_-]{3,20}$/.test(name);

// Авторизація через HTTP
app.post('/login', async (req, res) => {
    const { username } = req.body;
    if (!username || !validateName(username)) {
        return res.status(400).send('Username is required');
    }

    // Створюємо сесію для користувача
    req.session.userId = uuidv4();  // Генеруємо унікальний ID для користувача
    req.session.username = username;

    try {
        const updatedGroup = await Group.findOneAndUpdate(
            { name: 'general' },
            { $addToSet: { members: username } },
            { new: true }
        );

        if (!updatedGroup) {
            return res.status(404).send('Група не знайдена');
        }

    } catch (err) {
        console.error('Помилка при оновленні групи:', err);
        res.status(400).send('Помилка при оновленні групи');
    }


    return res.status(200).send({ message: 'Login successful', sessionId: req.session.userId });
});

// Функція для логування оновлень щодо чатів
const logMessage = (chatRoom, username, message, type = 'text') => {
    const logDirectory = path.join(__dirname, 'logs');
    const logFile = path.join(logDirectory, `${chatRoom}.log`);

    // Створюємо директорію, якщо її немає
    if (!fs.existsSync(logDirectory)) {
        fs.mkdirSync(logDirectory);
    }

    // Формуємо запис
    const logEntry = `[${new Date().toISOString()}] ${username} (${type}): ${message}\n`;

    // Записуємо запис у файл
    fs.appendFile(logFile, logEntry, (err) => {
        if (err) {
            console.error('Ошибка при записи в лог:', err);
        }
    });
};

// Оновлення серверу з HTTP запитів до WebSocket-з'єднання
server.on('upgrade', (request, socket, head) => {
    // Виймаємо sessionId з параметрів URL. Це значення має бути у запиті для автентифікації.
    const sessionId = new URL(request.url, `http://${request.headers.host}`).searchParams.get('sessionId');
    
    // Якщо sessionId відсутня, клієнт не авторизований.
    if (!sessionId) {
        // Відправляємо клієнту відповідь із кодом 401 Unauthorized і закриваємо з'єднання.
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
    }

    // Якщо sessionId існує, перевіряємо сесію за допомогою sessionParser.
    sessionParser(request, {}, () => {
        // Якщо сесія дійсна, продовжуємо процес апгрейду до WebSocket.
        wss.handleUpgrade(request, socket, head, (ws) => {
            // Після успішного апгрейду WebSocket-з'єднання, створюємо подію 'connection'.
            wss.emit('connection', ws, request);
        });
    });
});


// Основна логіка роботи WebSocket-з'єднання
wss.on('connection', async (ws, request) => {
    const userId = request.session.userId;
    const username = request.session.username;
    const path = request.url;

    ws.isAlive = true;
    ws.on('pong', () => (ws.isAlive = true)); // Підтримка зв'язку з клієнтом через пінг

    let chatRoom = 'general';
    const queryParams = new URLSearchParams(path.split('?')[1]);
    const sessionId = queryParams.get('sessionId');
    chatRoom = queryParams.get('chatRoom');

    ws.chatRoom = chatRoom;
    ws.username = username;

    try {
        // Шукаємо групу за назвою
        const group = await Group.findOne({ name: chatRoom });

        // Повідомляємо у чаті через БОТ, що користувач зайшов
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && client.chatRoom === chatRoom) {
                client.send(JSON.stringify({
                    type: 'newMessage',
                    message: {
                        chatRoom: group._id,
                        username: "BOT",
                        message: `User ${username} connected to this chat`,
                        timestamp: new Date()
                    },
                    chatRoomName: group.name
                }));
            }
        });

        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && client.chatRoom !== chatRoom && group.members.includes(client.username)) {
                client.send(JSON.stringify({
                    type: 'notification',
                    chatRoomName: group.name
                }));
            }
        });

        // Логування інформації про конект користувача
        logMessage(chatRoom,username, `User ${username} connected to this chat`);

        // Робимо запит groupList, щоб відобразити поточні чати користувача
        const groups = await Group.find({ members: { $in: [username] } });
        ws.send(JSON.stringify({ type: 'groupList', data: groups.map(group => group.name) }));

        // Валідація щодо шляхів групи
        if (!group) {
            console.error('Група не знайдена');
            ws.send(JSON.stringify({ type: 'groupAccessError' }));
            return;
        }

        if (!group.members.includes(username)) {
            console.error('Група недоступна');
            ws.send(JSON.stringify({ type: 'groupAccessError' }));
            return;
        }

        // Завантажуємо останні 20 повідомлень
        const lastMessages = await Message.find({ chatRoom: group._id })
            .sort({ timestamp: -1 })
            .limit(20);

        // Форматуємо аудіо, щоб голосові повідомлення можна було послухати
        const formattedMessages = lastMessages.reverse().map((msg) => {
            if (msg.audio) {
                return {
                    ...msg._doc,
                    audio: msg.audio.toString()
                };
            }
            return msg;
        });

        // відправляємо останні повідомлення
        ws.send(JSON.stringify({ type: 'prevMessages', data: formattedMessages }));

        // обробка отриманих запитів
        ws.on('message', async (message) => {
            const messageData = JSON.parse(message);

            // Перевірка автентифікації сесії
            if (!request.session.userId) {
                ws.send(JSON.stringify({ error: 'Unauthorized' }));
                return;
            }

            // Обробка різних типів повідомлень
            switch (messageData.type) {
                case 'getGroups':

                    // Отримуємо список груп із бази даних
                    try {
                        console.log(messageData)
                        const groups = await Group.find({ members: { $in: [username] } });
                        ws.send(JSON.stringify({ type: 'groupList', data: groups.map(group => group.name) }));
                    } catch (error) {
                        ws.send(JSON.stringify({ error: 'Помилка при отриманні списку груп' }));
                    }
                    break;

                case 'getMessages':
                    // Отримуємо всі повідомлення вибраної групи
                    try {
                        const selectedGroup = await Group.findOne({ name: messageData.chatRoom });
                        if (!selectedGroup) {
                            ws.send(JSON.stringify({ error: 'Група не знайдена' }));
                            return;
                        }

                        const groupMessages = await Message.find({ chatRoom: selectedGroup._id })
                            .sort({ timestamp: -1 })
                            .limit(20);

                        const formattedGroupMessages = groupMessages.reverse().map((msg) => {
                            if (msg.audio) {
                                return {
                                    ...msg._doc,
                                    audio: msg.audio.toString()
                                };
                            }
                            return msg;
                        });

                        ws.send(JSON.stringify({ type: 'groupMessages', data: formattedGroupMessages }));
                    } catch (error) {
                        ws.send(JSON.stringify({ error: 'Ошибка при получении сообщений группы' }));
                    }
                    break;

                case 'text':
                    // Обробляємо текстове повідомлення
                    const newMessage = new Message({
                        chatRoom: group._id,
                        username: messageData.username,
                        message: messageData.message,
                        timestamp: new Date()
                    });

                    await newMessage.save();

                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && client.chatRoom === chatRoom) {
                            client.send(JSON.stringify({
                                type: 'newMessage',
                                message: newMessage,
                                chatRoomName: group.name
                            }));
                        }
                    });

                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && client.chatRoom !== chatRoom && group.members.includes(client.username)) {
                            client.send(JSON.stringify({
                                type: 'notification',
                                chatRoomName: group.name
                            }));
                        }
                    });

                    logMessage(group.name,messageData.username, messageData.message);
                    break;

                case 'audio':
                    // Обробляємо аудіоповідомлення
                    const newAudioMessage = new Message({
                        chatRoom: group._id,
                        username: messageData.username,
                        audio: messageData.audio,
                        timestamp: new Date(),
                    });

                    await newAudioMessage.save();

                    const audioBase64 = newAudioMessage.audio.toString();

                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && client.chatRoom === chatRoom) {
                            client.send(JSON.stringify({
                                type: 'newAudioMessage',
                                message: {
                                    ...newAudioMessage.toObject(),
                                    audio: audioBase64
                                }
                            }));
                        }
                    });

                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && client.chatRoom !== chatRoom && group.members.includes(client.username)) {
                            client.send(JSON.stringify({
                                type: 'notification',
                                chatRoomName: group.name
                            }));
                        }
                    });
                    logMessage(group.name,messageData.username, "Uploaded audio!");
                    break;

                case 'createGroup':
                    // Створюємо нову групу
                    try {
                        const { groupName } = messageData;

                        if (!validateName(groupName)) {
                            ws.send(JSON.stringify({ error: 'Invalid group name' }));
                            return;
                        }


                        // Перевіряємо, чи існує група з таким ім'ям
                        const existingGroup = await Group.findOne({ name: groupName });
                        if (existingGroup) {
                            ws.send(JSON.stringify({ error: 'Group already exists' }));
                            return;
                        }

                        // Створюємо нову групу
                        const newGroup = new Group({
                            name: groupName,
                            members: [username],  // Автор групи додається як перший учасник
                        });

                        await newGroup.save();

                        const groups = await Group.find({ members: { $in: [username] } });
                        ws.send(JSON.stringify({ type: 'groupList', data: groups.map(group => group.name) }));

                        ws.send(JSON.stringify({ type: 'groupCreated', group: newGroup.name }));
                        logMessage(groupName, username, "New chat created!");
                    } catch (error) {
                        ws.send(JSON.stringify({ error: 'Error creating group' }));
                    }
                    break;


                case 'addMemberToGroup':
                    // Додаємо нового учасника до групи
                    try {
                        const { groupName, newMember } = messageData;

                        if (!validateName(newMember)) {
                            ws.send(JSON.stringify({ error: 'Invalid username' }));
                            return;
                        }

                        // Шукаємо групу на ім'я
                        const group = await Group.findOne({ name: groupName });
                        if (!group) {
                            ws.send(JSON.stringify({ error: 'Group not found' }));
                            return;
                        }

                        // Перевіряємо, якщо користувач вже у групі
                        if (group.members.includes(newMember)) {
                            ws.send(JSON.stringify({ error: 'User already in group' }));
                            return;
                        }

                        // Додаємо нового учасника до групи
                        group.members.push(newMember);
                        await group.save();

                        ws.send(JSON.stringify({ type: 'memberAdded', group: groupName, member: newMember }));

                        // Повідомляємо всіх учасників про нового учасника
                        wss.clients.forEach(client => {
                            if (client.readyState === WebSocket.OPEN) {
                                client.send(JSON.stringify({
                                    type: 'newMember',
                                    data: {
                                        group: groupName,
                                        member: newMember
                                    }
                                }));
                            }
                        });
                        logMessage(groupName, username, `Added new member - ${newMember}`);
                    } catch (error) {
                        ws.send(JSON.stringify({ error: 'Error adding member to group' }));
                    }
                    break;


                default:
                    ws.send(JSON.stringify({ error: 'Unknown message type' }));
            }
        });
    } catch (error) {
        console.error('Error:', error);
    }

    ws.on('close', async () => {
        try {
            const group = await Group.findOne({ name: chatRoom });
            console.log(`User ${username} disconnected from ${chatRoom}`);
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN && client.chatRoom === chatRoom) {
                    client.send(JSON.stringify({
                        type: 'newMessage',
                        message: {
                            chatRoom: group._id,
                            username: "BOT",
                            message: `User ${username} disconnected from this chat`,
                            timestamp: new Date()
                        },
                        chatRoomName: group.name
                    }));
                }
            });

            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN && client.chatRoom !== chatRoom && group.members.includes(client.username)) {
                    client.send(JSON.stringify({
                        type: 'notification',
                        chatRoomName: group.name
                    }));
                }
            });
            logMessage(group.name, username, `Disconnected from this chat`);
        } catch (error) {
            console.error('Error:', error);
        }
    });
});



// Підтримка сесії і пінгу для перевірки з'єднання
setInterval(() => {
    wss.clients.forEach((ws) => {
        if (!ws.isAlive) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, 3000);

// Запуск сервера
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
