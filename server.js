const express = require('express');
const app = express();

// Endpoint để ping (UptimeRobot sẽ gọi URL này)
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date(),
    message: 'Server is awake'
  });
});

// Hoặc nếu dùng frontend, thêm endpoint này:
app.get('/api/health', (req, res) => {
  res.status(200).send('OK');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});