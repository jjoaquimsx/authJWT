require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Model User
const User = require("../model/user.js");

// Open route - Public
app.get("/", (req, res) => {
  res.send("Ola mundo");
  res.status(200).json({ msg: "Bem vindo a api" });
});

//Private Route
app.get("/user/:id", checkToken, async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ msg: "ID invalido" });
  }

  //check user
  try {
    const user = await User.findById(id, "-password");

    if (!user) {
      return res.status(404).json({ msg: "Usuario nao encontrado" });
    }

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ msg: "Erro no servidor" });
  }
});

function checkToken(req, res, next){
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if(!token){
    return res.status(401).json({msg: "Acesso negado"})
  }
  try{
    const secret = process.env.SECRET

    jwt.verify(token, secret)

    next()
  }catch(error){
    res.status(400).json({msg: "Token invalido"})
  }
}

// Register User
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpass } = req.body;

  //validation
  if (!name) {
    return res.status(401).json({ msg: "Nome Obrigatorio" });
  }

  if (!email) {
    return res.status(401).json({ msg: "Email obrigatorio" });
  }

  if (!password) {
    return res.status(401).json({ msg: "Senha obrigatoria" });
  }

  if (password != confirmpass) {
    return res.status(401).json({
      msg: "as senhas nao conferem",
    });
  }

  //check email
  const userExist = await User.findOne({ email: email });

  if (userExist) {
    return res.status(401).json({ msg: "Por favor utilize outro e-mail" });
  }

  //create pass
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  //createUser
  const user = new User({
    name,
    email,
    password: passwordHash, // corrigido para usar "password"
  });

  try {
    await user.save();

    res.status(201).json({ msg: "Usuario criado com sucesso", });
  } catch (error) {
    res.status(500).json({ msg: "Erro inesperado tente novamente mais tarde" });
  }
});

//autenticates
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //validation
  if (!email) {
    return res.status(401).json({ msg: "Email obrigatorio" });
  }

  if (!password) {
    return res.status(401).json({ msg: "Senha obrigatoria" });
  }

  //check user
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ msg: "Email não encontrado" });
  }

  //check password match
  const checkPass = await bcrypt.compare(password, user.password);
  if (!checkPass) {
    return res.status(401).json({ msg: "Senha incorreta" });
  }

  try {
    const secret = process.env.SECRET;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res.status(200).json({ msg: "Autenticação feita", token });
  } catch (error) {
    console.log(error);

    res
      .status(500)
      .json({ msg: "Ocorreu um erro inesperado, tente novamente mais tarde" });
  }
});

//Credenciais
const dbUser = process.env.ACCES_API;

mongoose
  .connect(dbUser)
  .then(() => {
    app.listen(3000);
    console.log("Connected API");
  })
  .catch((err) => console.log(err));
