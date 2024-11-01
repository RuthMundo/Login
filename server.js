
const express = require("express");
const app = express();
const formidable = require("express-formidable");
const mongoose = require("mongoose");
const session = require('express-session');
const passportLocalMongoose = require("passport-local-mongoose");
const bcrypt = require("bcrypt");
const http = require("http").createServer(app);
const jwt = require("jsonwebtoken");
const socketIO = require("socket.io")(http);
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const passport = require("passport");
require('dotenv').config();

// Configuraciones
const accessTokenSecret = "myAccessTokenSecret1234567890";
const PORT = 3000;
const DB_URL = "mongodb://localhost:27017/my_social_network";

// Middleware
app.use(formidable());
app.use("/public", express.static(__dirname + "/public"));
app.set("view engine", "ejs");


app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true
}));

// Inicializamos passport
app.use(passport.initialize());
app.use(passport.session());

// Conexión a MongoDB
mongoose.connect(DB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Conectado a la base de datos.");
}).catch(err => {
    console.error("Error de conexión a la base de datos:", err);
});

// Esquema de Usuario
const userSchema = new mongoose.Schema({
    name: String,
    username: { type: String, unique: true },
    email: { type: String, unique: true },
    password: String,
    gender: String,
    profileImage: { type: String, default: "" },
    coverPhoto: { type: String, default: "" },
    dob: { type: String, default: "" },
    city: { type: String, default: "" },
    country: { type: String, default: "" },
    aboutMe: { type: String, default: "" },
    friends: { type: Array, default: [] },
    pages: { type: Array, default: [] },
    notifications: { type: Array, default: [] },
    groups: { type: Array, default: [] },
    posts: { type: Array, default: [] },
});

const User = mongoose.model("User", userSchema);

// Esquema de UsuarioGoogle
const usuarioSchema = new mongoose.Schema({
    username: String,
    googleId: String,
});

// HASH Y SALT
usuarioSchema.plugin(passportLocalMongoose);
usuarioSchema.plugin(findOrCreate);
//modelo de usuarios
const Usuario = mongoose.model("Usuario", usuarioSchema);
//creacion de stategy 
passport.use(Usuario.createStrategy());

// Serializar-deserializar
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        cb(null, { id: user.id });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

// Autenticación Google
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/updateProfile"
},
function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    Usuario.findOrCreate({ googleId: profile.id }, { username: profile.displayName }, function(err, user) {
        return cb(err, user);
    });
}));

// WebSocket
const socketClients = {};

const io = socketIO.on("connection", (socket) => {
    console.log("Usuario conectado:", socket.id);
    socketClients[socket.id] = socket;

    socket.on("disconnect", () => {
        console.log("Usuario desconectado:", socket.id);
        delete socketClients[socket.id];
    });
});

// Rutas
app.get("/signup", (req, res) => {
    res.render("signup");
});

app.post("/signup", async (req, res) => {
    const { name, username, email, password, gender } = req.fields;

    try {
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.json({
                status: "error",
                message: "El email o el nombre de usuario ya existe."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            name,
            username,
            email,
            password: hashedPassword,
            gender
        });

        await newUser.save();
        res.json({
            status: "success",
            message: "Registro exitoso. Puedes iniciar sesión ahora."
        });
    } catch (error) {
        console.error("Error al registrar el usuario:", error);
        res.json({
            status: "error",
            message: "Error al guardar el usuario."
        });
    }
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", async (req, res) => {
    const { email, password } = req.fields;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({
                status: "error",
                message: "El email no existe."
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.json({
                status: "error",
                message: "La contraseña no es correcta."
            });
        }

        const accessToken = jwt.sign({ email }, accessTokenSecret);
        user.accessToken = accessToken; // Guarda el token en el usuario, si es necesario
        await user.save(); // Guarda los cambios en la base de datos

        res.json({
            status: "success",
            message: "Inicio de sesión exitoso.",
            accessToken,
            profileImage: user.profileImage
        });
    } catch (error) {
        console.error("Error en el inicio de sesión:", error);
        res.json({
            status: "error",
            message: "Error en el inicio de sesión."
        });
    }
});

app.get("/updateProfile", (req, res) => {
    res.render("updateProfile");
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect("/login");
    });
});

// Autenticación de Google
app.get('/auth/google', 
    passport.authenticate('google', { scope: ['email', 'profile'] })
);
//callback
app.get("/auth/google/updateProfile", 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
        res.redirect("/updateProfile");
    }
);

// Iniciar el servidor
http.listen(PORT, () => {
    console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
