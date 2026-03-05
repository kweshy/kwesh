const crypto = require("crypto");
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const pool = require('./db.JS'); // your PostgreSQL connection file

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static('public'));
/* ============================
   GMAIL NODEMAILER SETUP
============================ */

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false  // <- ignore self-signed certificate
  }
});



/* ============================
   REGISTER ROUTE
============================ */

app.post("/api/register", async (req, res) => {
  const { fullname, role, grade_group, email, password } = req.body;

  // 1️⃣ Basic checks
  if (!fullname || !role || !email || !password) {
    return res.status(400).json({ message: "Full name, role, email, and password are required" });
  }

  // 2️⃣ Teachers must have a grade group
  if (role === "Teacher" && (!grade_group || grade_group === "")) {
    return res.status(400).json({ message: "Grade group is required for teachers" });
  }

  try {
    // 3️⃣ Enforce only one Admin
    if (role === "Admin") {
      const existingAdmin = await pool.query("SELECT * FROM users WHERE role = $1", ["Admin"]);
      if (existingAdmin.rows.length > 0) {
        return res.status(400).json({ message: "An Admin already exists" });
      }
    }

    // 4️⃣ Check if email already exists
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // 5️⃣ Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 6️⃣ Insert user (Admin grade_group can be null)
    const dbGradeGroup = role === "Teacher" ? grade_group : null;
    await pool.query(
      `INSERT INTO users (fullname, role, grade_group, email, password)
       VALUES ($1, $2, $3, $4, $5)`,
      [fullname, role, dbGradeGroup, email, hashedPassword]
    );

    // 7️⃣ Send welcome email
    await transporter.sendMail({
      from: '"Little Innovators" <yourschool.system@gmail.com>',
      to: email,
      subject: "Account Created Successfully",
      html: `
        <h3>Hello ${fullname},</h3>
        <p>Your account has been created successfully.</p>
        <p>You can now log in using your email.</p>
      `
    });

    res.json({ message: "Registration successful" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});



/* ============================
   LOGIN ROUTE
============================ */

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  try {
    // Fetch user by email
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Email not found" });
    }

    const user = result.rows[0];

    // Compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect password" });
    }

    // Return role and grade_group for dashboard redirection
    res.json({
      message: "Login successful",
      user: {
        id: user.id,
        fullname: user.fullname,
        role: user.role,
        grade_group: user.grade_group // this is key for teacher redirection
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/check-admin", async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE role = $1',
      ['Admin']
    );
    res.json({ adminExists: result.rows.length > 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ adminExists: false });
  }
});
app.post("/api/send-verification", async (req, res) => {
  const { email } = req.body;

  // generate 6-digit code
  const code = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    await transporter.sendMail({
      from: '"Little Innovators" <your-email@gmail.com>',
      to: email,
      subject: "Email Verification",
      html: `<p>Your verification code is: <b>${code}</b></p>`
    });

    // send code back for frontend comparison (simple, for demo)
    res.json({ success: true, code });
  } catch (err) {
    console.error(err);
    res.json({ success: false });
  }
});

/* ============================
   FORGOT PASSWORD
============================ */

app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    // Always return same message (security)
    const genericMessage = {
      message: "If the email exists, a reset link has been sent."
    };

    // Check if user exists
    const user = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (user.rows.length === 0) {
      return res.json(genericMessage);
    }

    // Generate secure token
    const token = crypto.randomBytes(32).toString("hex");

    // Expiry (15 minutes)
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    // Store token
    await pool.query(
      `INSERT INTO password_resets (email, token, expires_at)
       VALUES ($1, $2, $3)`,
      [email, token, expires]
    );

    // Reset link
    const resetLink = `http://localhost:3000/reset-password.html?token=${token}`;

    // Send email
    await transporter.sendMail({
      from: '"Little Innovators" <your-email@gmail.com>',
      to: email,
      subject: "Password Reset",
      html: `
        <p>You requested a password reset.</p>
        <p>Click the link below to reset your password:</p>
        <a href="${resetLink}">${resetLink}</a>
        <p>This link expires in 15 minutes.</p>
      `
    });

    res.json(genericMessage);

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ============================
   RESET PASSWORD
============================ */

app.post("/api/reset-password", async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res.status(400).json({ message: "Invalid request" });
  }

  try {
    // Find token
    const result = await pool.query(
      "SELECT * FROM password_resets WHERE token = $1",
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    const reset = result.rows[0];

    // Check expiry
    if (new Date(reset.expires_at) < new Date()) {
      return res.status(400).json({ message: "Token expired" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user password
    await pool.query(
      "UPDATE users SET password = $1 WHERE email = $2",
      [hashedPassword, reset.email]
    );

    // Delete used token
    await pool.query(
      "DELETE FROM password_resets WHERE token = $1",
      [token]
    );

    res.json({ message: "Password reset successful" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ----------------------
// STUDENT ROUTES
// ----------------------

// GET single student by ID
app.get("/students/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query("SELECT * FROM students WHERE id = $1", [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Student not found" });
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error" });
    }
});
// Create new students
app.post("/students", async (req, res) => {
    const { full_name, grade, parent_name, parent_phone, teacher_id } = req.body;

    try {
        const result = await pool.query(
            `INSERT INTO students 
             (full_name, grade, parent_name, parent_phone, teacher_id)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *`,
            [full_name, grade, parent_name, parent_phone, teacher_id]
        );

        res.status(201).json(result.rows[0]);

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error" });
    }
});

// UPDATE student by ID
app.put("/students/:id", async (req, res) => {
    const { id } = req.params;
    const { full_name, grade, parent_name, parent_phone } = req.body;

    try {
        const result = await pool.query(
            `UPDATE students
             SET full_name=$1, grade=$2, parent_name=$3, parent_phone=$4
             WHERE id=$5
             RETURNING *`,
            [full_name, grade, parent_name, parent_phone, id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: "Student not found" });
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error" });
    }
});

// DELETE student by ID
app.delete("/students/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query("DELETE FROM students WHERE id=$1 RETURNING *", [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Student not found" });
        res.json({ message: "Student deleted" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error" });
    }
});

// Fetch all registered students (full names only)
app.get('/api/students', async (req, res) => {

    const teacherId = req.query.teacher_id;

    try {

        const result = await pool.query(
            `SELECT id, full_name
             FROM students
             WHERE teacher_id = $1`,
            [teacherId]
        );

        res.json(result.rows);

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch students' });
    }
});


app.post('/api/attendance', async (req, res) => {
    const { records } = req.body;

    if (!records || !Array.isArray(records)) {
        return res.status(400).json({ success: false, message: 'Invalid data' });
    }

    try {
        const queryText = `
            INSERT INTO attendance (student_id, date, status)
            VALUES ($1, $2, $3)
            ON CONFLICT (student_id, date)
            DO UPDATE SET status = EXCLUDED.status
        `;

        for (const rec of records) {
            await pool.query(queryText, [rec.student_id, rec.date, rec.status]);
        }

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

// GET attendance records by date
app.get('/api/attendance', async (req, res) => {
    const date = req.query.date;
    const teacherId = req.query.teacher_id;

    if (!date) return res.status(400).json({ success: false, message: 'Date required' });
    if (!teacherId) return res.status(400).json({ success: false, message: 'teacher_id required' });

    try {
        const result = await pool.query(
            `SELECT a.student_id, a.status
             FROM attendance a
             JOIN students s ON a.student_id = s.id
             WHERE a.date = $1 AND s.teacher_id = $2`,
            [date, teacherId]
        );

        res.json({ success: true, records: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Database error' });
    }
});


// Endpoint to get attendance summary
app.get("/api/attendance-summary", async (req, res) => {
  try {
    const date = req.query.date || new Date().toISOString().split("T")[0];
    const teacherId = req.query.teacher_id;

    if (!teacherId) return res.status(400).json({ message: "teacher_id required" });

    // Count total students for this teacher
    const totalResult = await pool.query(
      "SELECT COUNT(*) AS total FROM students WHERE teacher_id = $1",
      [teacherId]
    );
    const totalStudents = parseInt(totalResult.rows[0].total, 10);

    // Count attendance for these students only
    const statusResult = await pool.query(
      `SELECT a.status, COUNT(*) AS count
       FROM attendance a
       JOIN students s ON a.student_id = s.id
       WHERE a.date = $1 AND s.teacher_id = $2
       GROUP BY a.status`,
      [date, teacherId]
    );

    let present = 0, absent = 0, late = 0;
    statusResult.rows.forEach(row => {
      if (row.status === "Present") present += parseInt(row.count, 10);
      if (row.status === "Absent") absent += parseInt(row.count, 10);
      if (row.status === "Late") {
        late += parseInt(row.count, 10);
        present += parseInt(row.count, 10); // Late counts as present
      }
    });

    const attendanceRate = totalStudents > 0
      ? ((present / totalStudents) * 100).toFixed(2)
      : 0;

    res.json({ totalStudents, present, absent, late, attendanceRate });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/total-students/:className', async (req, res) => {
    const teacherId = req.query.teacher_id; // get teacher ID from frontend
    const { className } = req.params;

    if (!teacherId) return res.status(400).json({ message: "teacher_id required" });

    try {
        const result = await pool.query(
            'SELECT total_students FROM class_info WHERE class_name = $1 AND teacher_id = $2',
            [className, teacherId]
        );

        if (result.rows.length === 0) return res.json({ total: 0 }); // no record yet
        res.json({ total: result.rows[0].total_students });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/set-total', async (req, res) => {
    const { className, total, teacher_id } = req.body;

    if (!className || !total || !teacher_id) {
        return res.status(400).json({ message: 'Missing data' });
    }

    try {
        await pool.query(
            `INSERT INTO class_info (class_name, total_students, teacher_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (class_name, teacher_id)
             DO UPDATE SET total_students = EXCLUDED.total_students`,
            [className, total, teacher_id]
        );

        res.json({ message: 'Total students updated successfully!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});


app.get("/students", async (req, res) => {
    const teacherId = req.query.teacher_id;

    try {
        const { rows } = await pool.query(
            "SELECT * FROM students WHERE teacher_id = $1",
            [teacherId]
        );

        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error" });
    }
});

// Get all homework
app.get('/api/homework', async (req, res) => {
  const teacherId = req.query.teacherId;

  if (!teacherId) {
    return res.status(400).json({ message: "teacherId required" });
  }

  try {
    const result = await pool.query(
      `SELECT id, subject, title, description, due_date, teacher_id
       FROM homework
       WHERE teacher_id = $1
       ORDER BY due_date ASC`,
      [teacherId]
    );

    res.json(result.rows); // ✅ VERY IMPORTANT
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to fetch homework' });
  }
});

// 
app.post('/api/homework', async (req, res) => {
  const { subject, title, description, dueDate, teacher_id, active } = req.body;

  if (!subject || !title || !dueDate) {
    return res.status(400).json({ message: 'Subject, title, and due date required' });
  }

  const teacherId = Number(teacher_id); // ensure integer
  const isActive = active === true || active === "true"; // ensure boolean

  try {
    const result = await pool.query(
      `INSERT INTO homework (subject, title, description, due_date, teacher_id, active)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [subject, title, description, dueDate, teacherId, isActive] // ✅ 6 VALUES
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});
// DELETE EXISTING HOMEWORKS
app.delete('/api/homework/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM homework WHERE id=$1', [id]);
    res.json({ message: 'Homework deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* ============================
   ASSIGN HOMEWORK TO STUDENTS
============================ */

app.post("/api/assign-homework", async (req, res) => {

  const { homeworkId, students } = req.body;

  if (!homeworkId || !students || students.length === 0) {
    return res.status(400).json({
      message: "Missing homework or students"
    });
  }

  try {

    for (const studentId of students) {

      await pool.query(
        `INSERT INTO homework_assignments
         (homework_id, student_id)
         VALUES ($1, $2)
         ON CONFLICT (homework_id, student_id)
         DO NOTHING`,
        [homeworkId, studentId]
      );
    }

    res.json({
      message: "Homework assigned successfully"
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Assignment failed"
    });
  }
});

app.get("/api/homework-assigned/:homeworkId", async (req, res) => {
  const { homeworkId } = req.params;
  console.log("Fetching assigned students for homeworkId:", homeworkId);

  try {
    const result = await pool.query(
      `SELECT student_id FROM homework_assignments WHERE homework_id = $1`,
      [homeworkId]
    );

    const assignedIds = result.rows.map(r => r.student_id);
    console.log("Assigned IDs:", assignedIds);

    res.json(assignedIds);
  } catch (err) {
    console.error("ERROR in /api/homework-assigned:", err);
    res.status(500).json({ message: "Failed to fetch assigned students" });
  }
});

// GET all students for a specific teacher (for assigning homework)
app.get("/api/students-for-homework", async (req, res) => {
  const teacherId = req.query.teacher_id; // get teacher ID from query

  if (!teacherId) {
    return res.status(400).json({ message: "teacher_id required" });
  }

  try {
    const result = await pool.query(
      `SELECT id, full_name, parent_phone
       FROM students
       WHERE teacher_id = $1
       ORDER BY full_name ASC`,
      [teacherId]
    );

    res.json(result.rows); // send array of students
  } catch (err) {
    console.error("Error fetching students for homework:", err);
    res.status(500).json({ message: "Failed to fetch students" });
  }
});
// Unassign selected students from a specific homework
app.post("/api/unassign-homework", async (req, res) => {
  const { homeworkId, students } = req.body;

  if (!homeworkId || !students || students.length === 0) {
    return res.status(400).json({ message: "Missing homework or students" });
  }

  try {
    for (const studentId of students) {
      await pool.query(
        `DELETE FROM homework_assignments
         WHERE homework_id = $1 AND student_id = $2`,
        [homeworkId, studentId]
      );
    }

    res.json({ message: "Selected students unassigned successfully" });
  } catch (err) {
    console.error("Error unassigning students:", err);
    res.status(500).json({ message: "Failed to unassign students" });
  }
});

// Fetching homework in dashboard 
app.get('/api/dashboard/homework', async (req, res) => {
  const { teacherId } = req.query; // get teacher ID from frontend

  try {
    const result = await pool.query(
      `SELECT COUNT(*) AS active_homework_count
       FROM homework
       WHERE teacher_id = $1 AND active = true`,
      [teacherId]
    );

    const count = parseInt(result.rows[0].active_homework_count, 10);
    res.json({ activeHomeworkCount: count });

  } catch (err) {
    console.error("Error fetching active homework:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET ALL EVENTS
app.get("/events", async (req, res) => {
  const { teacherId } = req.query;

  let query = "SELECT * FROM events";
  const params = [];

  if (teacherId) {
    query += " WHERE teacher_id = $1";
    params.push(teacherId);
  }

  query += " ORDER BY event_date";

  try {
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ADD EVENT
app.post("/events", async (req, res) => {

const { title, date, time, type, description, teacherId } = req.body;

const result = await pool.query(
`INSERT INTO events (title,event_date,event_time,type,description,teacher_id)
VALUES ($1,$2,$3,$4,$5,$6)
RETURNING *`,
[title, date, time, type, description, teacherId]
);

res.json(result.rows[0]);

});
// DELETE EVENT
app.delete("/events/:id", async (req, res) => {

const { id } = req.params;

await pool.query(
"DELETE FROM events WHERE id = $1",
[id]
);

res.json({ message: "Event deleted" });

});
/* ============================
   SERVER START
============================ */

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
