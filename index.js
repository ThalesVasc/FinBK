const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const prisma = new PrismaClient();
const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "segredo";

// --- ROTAS ---

app.get("/", (req, res) => {
  res.send("Backend funcionando!");
});


// Registrar usuário
app.post("/register", async (req, res) => {
  const { nome, email, senha } = req.body;

  if (!nome || !email || !senha) {
    return res.status(400).json({ error: "Preencha todos os campos" });
  }

  const hash = await bcrypt.hash(senha, 8);

  try {
    const user = await prisma.user.create({
      data: { nome, email, senha: hash },
    });
    res.json({ message: "Usuário registrado com sucesso" });
  } catch (err) {
    res.status(400).json({ error: "E-mail já cadastrado" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, senha } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(400).json({ error: "Usuário não encontrado" });

  const isValid = await bcrypt.compare(senha, user.senha);
  if (!isValid) return res.status(400).json({ error: "Senha inválida" });

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1d" });
  res.json({ user: { id: user.id, nome: user.nome, email: user.email }, token });
});

// Middleware para autenticação
function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token necessário" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// Lista de produtos
app.get("/produtos", auth, async (req, res) => {
  const produtos = await prisma.produto.findMany();
  res.json(produtos);
});

// Inicializar servidor
app.listen(3000, () => {
  console.log("Backend rodando na porta 3000");
});
