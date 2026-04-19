require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
const Razorpay = require("razorpay");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
app.set("view engine", "ejs");

app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

// DB
const db = new sqlite3.Database("./database.db");

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT,
  password TEXT,
  role TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY,
  title TEXT,
  description TEXT,
  price INTEGER,
  type TEXT,
  images TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY,
  product_id INTEGER,
  email TEXT,
  amount INTEGER,
  status TEXT DEFAULT 'processing'
)`);

// Admin create
(async () => {
  const hash = await bcrypt.hash("Admin@123", 10);
  db.run(`INSERT OR IGNORE INTO users (username,password,role)
    VALUES ('esterlangrynjah@gmail.com', ?, 'admin')`, [hash]);
})();

// Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Email
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Middleware
function requireAdmin(req, res, next) {
  if (req.session.user?.role === "admin") return next();
  res.send("Access denied");
}

// Home
app.get("/", (req, res) => {
  db.all("SELECT * FROM projects", (err, projects) => {
    res.render("index", { projects, user: req.session.user });
  });
});

// Login
app.get("/login", (req, res) => res.render("login"));

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username=?", [username], async (err, user) => {
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.user = user;
      res.redirect("/");
    } else res.send("Invalid");
  });
});

// Admin add product
const upload = multer({ dest: "uploads/" });

app.post("/admin/add", requireAdmin, upload.single("image"), (req, res) => {
  const { title, description, price, type } = req.body;

  db.run(
    "INSERT INTO projects (title,description,price,type,images) VALUES (?,?,?,?,?)",
    [title, description, price, type, req.file.filename],
    () => res.redirect("/")
  );
});

// Buy page
app.get("/buy/:id", (req, res) => {
  db.get("SELECT * FROM projects WHERE id=?", [req.params.id], (err, product) => {
    res.render("buy", { product });
  });
});

// Razorpay order
app.post("/create-order", async (req, res) => {
  const order = await razorpay.orders.create({
    amount: req.body.amount * 100,
    currency: "INR"
  });
  res.json(order);
});

// Verify payment
app.post("/verify", (req, res) => {
  const { order_id, payment_id, signature } = req.body;

  const body = order_id + "|" + payment_id;

  const expected = crypto
    .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
    .update(body)
    .digest("hex");

  if (expected === signature) {
    db.run("INSERT INTO orders (product_id,email,amount) VALUES (?,?,?)",
      [req.body.product_id, req.body.email, req.body.amount]);

    transporter.sendMail({
      to: req.body.email,
      subject: "Order Confirmed",
      html: "<h2>Order Successful</h2>"
    });

    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// Orders admin
app.get("/admin/orders", requireAdmin, (req, res) => {
  db.all("SELECT * FROM orders", (err, orders) => {
    res.render("orders", { orders });
  });
});

app.listen(3000, () => console.log("Running"));
