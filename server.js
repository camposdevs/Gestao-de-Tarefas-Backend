const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB conectado!'))
  .catch(err => console.error(err));

// Models
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
    res.status(400).json({ error: 'Email já cadastrado' });
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
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Rotas de Tarefas (protegidas)
app.get('/api/tasks', authMiddleware, async (req, res) => {
  const tasks = await Task.find({ userId: req.userId }).sort({ createdAt: -1 });
  res.json(tasks);
});

app.post('/api/tasks', authMiddleware, async (req, res) => {
  const task = await Task.create({ ...req.body, userId: req.userId });
  res.json(task);
});

app.put('/api/tasks/:id', authMiddleware, async (req, res) => {
  const task = await Task.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(task);
});

app.delete('/api/tasks/:id', authMiddleware, async (req, res) => {
  await Task.findByIdAndDelete(req.params.id);
  res.json({ message: 'Deletado' });
});

app.listen(process.env.PORT, () => console.log(`Servidor rodando na porta ${process.env.PORT}`));