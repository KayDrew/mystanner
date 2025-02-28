// Import dotenv to load the encryption key from a .env file
require('dotenv').config();

// Hypothetical Metagraph API endpoint and token
const METAGRAPH_API_URL = 'https://api.metagraph.com/v1/facebook/posts';
const ACCESS_TOKEN = 'YOUR_ACCESS_TOKEN';

// Encryption key loaded from .env file
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Function to encrypt data using AES-GCM
async function encryptData(data) {
    try {
        // Convert the encryption key from the .env file to a CryptoKey
        const key = await crypto.subtle.importKey(
            'raw',
            Buffer.from(ENCRYPTION_KEY, 'hex'),
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        // Convert data to a Uint8Array
        const encodedData = new TextEncoder().encode(JSON.stringify(data));

        // Generate a random initialization vector (IV)
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // Encrypt the data
        const encryptedData = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encodedData
        );

        // Combine the IV and encrypted data for storage
        const combined = new Uint8Array(iv.length + encryptedData.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encryptedData), iv.length);

        // Return the encrypted data as a base64 string
        return Buffer.from(combined).toString('base64');
    } catch (error) {
        console.error('Encryption failed:', error);
        throw error;
    }
}

// Function to fetch reactions for the last 10 posts
async function fetchReactions() {
    try {
        // Fetch the last 10 posts
        const response = await fetch(`${METAGRAPH_API_URL}?access_token=${ACCESS_TOKEN}&limit=10`);
        const posts = await response.json();

        // Object to store reactions by user
        const reactionsByUser = {};

        // Loop through each post
        for (const post of posts) {
            // Fetch reactions for the post
            const reactionsResponse = await fetch(`${METAGRAPH_API_URL}/${post.id}/reactions?access_token=${ACCESS_TOKEN}`);
            const reactions = await reactionsResponse.json();

            // Count reactions by user
            for (const reaction of reactions) {
                const userName = reaction.user.name;
                if (reactionsByUser[userName]) {
                    reactionsByUser[userName]++;
                } else {
                    reactionsByUser[userName] = 1;
                }
            }
        }

        // Convert the object to an array and sort by reaction count in descending order
        const sortedReactions = Object.entries(reactionsByUser)
            .map(([name, count]) => ({ name, count }))
            .sort((a, b) => b.count - a.count);

        // Encrypt the sorted reactions data
        const encryptedData = await encryptData(sortedReactions);

        // Display the encrypted data
        console.log('Encrypted Data:', encryptedData);

    } catch (error) {
        console.error('Error fetching or encrypting reactions:', error);
    }
}

// Run the function
fetchReactions();