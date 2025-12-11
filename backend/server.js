const express = require('express');
const cors = require('cors');
const { launchFullExploitation } = require('./orchestrator');
const logger = require('./utils/logger');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

app.post('/api/exploit', async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ error: 'Domain required' });
  }

  try {
    logger.info(`Starting exploitation for ${domain}`);
    const results = await launchFullExploitation(domain);
    res.json(results);
  } catch (error) {
    logger.error(`Error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  logger.info(`🌑 Exploitation engine running on port ${PORT}`);
});

module.exports = app;
