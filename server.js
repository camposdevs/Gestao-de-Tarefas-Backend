const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Configuração do CORS aberta para evitar bloqueios entre Netlify e Render
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Rota inicial de teste (Health Check) para garantir que o Render veja o app online
app.get('/', (req, res) => {
  res.send('Backend do Gestor de Tarefas rodando com sucesso!');
});

// Modelos
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  createdAt: { type: Date, default: Date.now }
});

const TaskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  category: { type: String, default: 'Geral' },
  priority: { type: String, enum: ['baixa', 'media', 'alta'], default: 'media' },
  completed: { type: Boolean, default: false },
  dueDate: Date,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Task = mongoose.model('Task', TaskSchema);

// Middleware de autenticação
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
};

// Rotas de Auth
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name, email } });
  } catch (err) {
    res.status(400).json({ error: 'Email já cadastrado ou dados inválidos' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Credenciais inválidas' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email } });
  } catch (err) {
    // Retorna o erro real no console do backend para descobrirmos o problema
    console.error("Erro no login:", err);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Rotas de Tarefas (protegidas e seguras por ID de usuário)
app.get('/api/tasks', authMiddleware, async (req, res) => {
  const tasks = await Task.find({ userId: req.userId }).sort({ createdAt: -1 });
  res.json(tasks);
});

app.post('/api/tasks', authMiddleware, async (req, res) => {
  const task = await Task.create({ ...req.body, userId: req.userId });
  res.json(task);
});

app.put('/api/tasks/:id', authMiddleware, async (req, res) => {
  const task = await Task.findOneAndUpdate({ _id: req.params.id, userId: req.userId }, req.body, { new: true });
  if (!task) return res.status(404).json({ error: 'Tarefa não encontrada ou não autorizada' });
  res.json(task);
});

app.delete('/api/tasks/:id', authMiddleware, async (req, res) => {
  const task = await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
  if (!task) return res.status(404).json({ error: 'Tarefa não encontrada ou não autorizada' });
  res.json({ message: 'Deletado com sucesso' });
});

// CONFIGURAÇÃO DE CONEXÃO RECOMENDADA:
// O servidor só abre as portas se o banco de dados responder com sucesso!
const PORT = process.env.PORT || 10000;

mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✅ Conectado ao MongoDB com sucesso!');
    app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));
  })
  .catch(err => {
    console.error('❌ ERRO CRÍTICO AO CONECTAR NO MONGO:', err.message);
  });