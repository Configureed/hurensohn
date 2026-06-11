import express from 'express';
import path from 'path';
import Discord from 'discord.js-selfbot-v13';
import { create, load } from './src/src';
import cors from 'cors';

const app = express();
const PORT = 3002;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let client: Discord.Client | null = null;

// Endpoint to login with token
app.post('/api/login', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.status(400).json({ error: 'Token is required' });
        }

        client = new Discord.Client({
            checkUpdate: false,
            partials: [],
        });

        client.on('ready', () => {
            const servers = client!.guilds.cache.map(guild => ({
                id: guild.id,
                name: guild.name,
                iconURL: guild.iconURL({ dynamic: true })
            }));
            res.json({ success: true, username: client!.user!.tag, servers });
        });

        client.on('error', (error) => {
            res.status(500).json({ error: error.message });
        });

        await client.login(token);
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

// Endpoint to get servers
app.get('/api/servers', (req, res) => {
    if (!client || !client.readyAt) {
        return res.status(401).json({ error: 'Not logged in' });
    }
    const servers = client.guilds.cache.map(guild => ({
        id: guild.id,
        name: guild.name,
        iconURL: guild.iconURL({ dynamic: true })
    }));
    res.json({ servers });
});

// Endpoint to clone server
app.post('/api/clone', async (req, res) => {
    try {
        if (!client || !client.readyAt) {
            return res.status(401).json({ error: 'Not logged in' });
        }

        const { sourceServerId, targetServerId } = req.body;

        const sourceGuild = client.guilds.cache.get(sourceServerId);
        const targetGuild = client.guilds.cache.get(targetServerId);

        if (!sourceGuild) {
            return res.status(404).json({ error: 'Source server not found' });
        }

        if (!targetGuild) {
            return res.status(404).json({ error: 'Target server not found' });
        }

        res.json({ success: true, message: 'Cloning started' });

        // Create backup
        const backupData = await create(sourceGuild);

        // Load backup into target server (pass the backup data directly)
        await load(backupData, targetGuild);

        console.log('Cloning completed!');
    } catch (error: any) {
        console.error('Cloning error:', error);
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
