const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();
const morgan = require("morgan");
const winston = require("winston");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

mongoose
  .connect(process.env.MONGODB_URI || "mongodb://localhost:27017/car-rental-app", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Logger setup
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
    }),
  ],
});
app.use(morgan(":method :url :status :response-time ms - :res[content-length]"));

app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    const duration = Date.now() - start;
    logger.info({
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${duration}ms`,
      params: req.params,
      query: req.query,
      body: req.method !== "GET" ? req.body : undefined,
    });
  });
  next();
});

// ---- MODELS ----

// User Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' }
});
const User = mongoose.model('User', userSchema);

// Car Model
const carSchema = new mongoose.Schema(
  {
    model: { type: String, required: true },
    brand: { type: String, required: true },
    registrationNo: { type: String, required: true, unique: true },
    pricePerDay: { type: Number, required: true },
    status: { type: String, enum: ["available", "rented"], default: "available" },
  },
  { timestamps: true }
);
const Car = mongoose.model("Car", carSchema);

// Booking Model
const bookingSchema = new mongoose.Schema(
  {
    customerName: { type: String, required: true },
    car: { type: mongoose.Schema.Types.ObjectId, ref: "Car", required: true },
    rentFrom: { type: Date, required: true },
    rentTo: { type: Date, required: true },
    status: { type: String, enum: ["active", "completed", "cancelled"], default: "active" },
  },
  { timestamps: true }
);
const Booking = mongoose.model("Booking", bookingSchema);

// ---- AUTH MIDDLEWARE ----
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  jwt.verify(token, process.env.JWT_SECRET || "your_jwt_secret", (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Unauthorized' });
    req.user = decoded;
    next();
  });
}

// ---- AUTH ROUTES ----

// Signup
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hash, role });
    await user.save();
    res.status(201).json({ message: "User registered" });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ message: "Invalid credentials" });
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET || "your_jwt_secret",
      { expiresIn: "1h" }
    );
    res.json({ token, user: { username: user.username, role: user.role } });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Settings (profile update)
app.put("/api/auth/settings", authMiddleware, async (req, res) => {
  try {
    const { password } = req.body;
    const hash = password ? await bcrypt.hash(password, 10) : undefined;
    const update = password ? { password: hash } : {};
    const user = await User.findByIdAndUpdate(req.user.id, update, { new: true });
    res.json({ message: "Settings updated.", user: { username: user.username, role: user.role } });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// ---- CRUD ROUTES ----

// Car Routes
app.get("/api/cars", authMiddleware, async (req, res) => {
  try {
    const cars = await Car.find().sort({ brand: 1, model: 1 });
    res.json(cars);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/api/cars", authMiddleware, async (req, res) => {
  try {
    const car = new Car(req.body);
    const savedCar = await car.save();
    res.status(201).json(savedCar);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put("/api/cars/:id", authMiddleware, async (req, res) => {
  try {
    const car = await Car.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!car) return res.status(404).json({ message: "Car not found" });
    res.json(car);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.delete("/api/cars/:id", authMiddleware, async (req, res) => {
  try {
    const bookings = await Booking.countDocuments({ car: req.params.id, status: "active" });
    if (bookings > 0) {
      return res.status(400).json({ message: "Cannot delete car with active bookings" });
    }
    const car = await Car.findByIdAndDelete(req.params.id);
    if (!car) return res.status(404).json({ message: "Car not found" });
    res.json({ message: "Car deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/cars/:id", authMiddleware, async (req, res) => {
  try {
    const car = await Car.findById(req.params.id);
    if (!car) return res.status(404).json({ message: "Car not found" });
    res.json(car);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Booking Routes
app.get("/api/bookings", authMiddleware, async (req, res) => {
  try {
    const bookings = await Booking.find().populate("car");
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/api/bookings", authMiddleware, async (req, res) => {
  try {
    const booking = new Booking(req.body);
    const savedBooking = await booking.save();
    await Car.findByIdAndUpdate(booking.car, { status: "rented" });
    res.status(201).json(savedBooking);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.put("/api/bookings/:id", authMiddleware, async (req, res) => {
  try {
    const booking = await Booking.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(booking);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.delete("/api/bookings/:id", authMiddleware, async (req, res) => {
  try {
    const booking = await Booking.findByIdAndDelete(req.params.id);
    if (!booking) return res.status(404).json({ message: "Booking not found" });
    await Car.findByIdAndUpdate(booking.car, { status: "available" });
    res.json({ message: "Booking deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/bookings/:id", authMiddleware, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id).populate("car");
    if (!booking) return res.status(404).json({ message: "Booking not found" });
    res.json(booking);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Dashboard Stats
app.get("/api/dashboard/stats", authMiddleware, async (req, res) => {
  try {
    const totalCars = await Car.countDocuments();
    const availableCars = await Car.countDocuments({ status: "available" });
    const totalBookings = await Booking.countDocuments();
    const activeBookings = await Booking.countDocuments({ status: "active" });
    res.json({
      totalCars,
      availableCars,
      totalBookings,
      activeBookings,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Health Endpoints - unchanged
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "UP",
    timestamp: new Date(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || "development",
  });
});
app.get('/health/detailed', async (req, res) => {
    try {
        const dbStatus = mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected';
        const systemInfo = {
            memory: {
                total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
                used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                unit: 'MB'
            },
            uptime: {
                seconds: Math.round(process.uptime()),
                formatted: formatUptime(process.uptime())
            },
            nodeVersion: process.version,
            platform: process.platform
        };
        const healthCheck = {
            status: 'UP',
            timestamp: new Date(),
            database: {
                status: dbStatus,
                name: 'MongoDB',
                host: mongoose.connection.host
            },
            system: systemInfo,
            environment: process.env.NODE_ENV || 'development'
        };
        res.status(200).json(healthCheck);
    } catch (error) {
        res.status(500).json({
            status: 'DOWN',
            timestamp: new Date(),
            error: error.message
        });
    }
});
function formatUptime(seconds) {
    const days = Math.floor(seconds / (3600 * 24));
    const hours = Math.floor((seconds % (3600 * 24)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainingSeconds = Math.floor(seconds % 60);
    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (remainingSeconds > 0) parts.push(`${remainingSeconds}s`);
    return parts.join(' ');
}
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
