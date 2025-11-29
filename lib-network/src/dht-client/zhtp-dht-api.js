/**
 * ZHTP DHT API Bridge
 * 
 * Provides the API interface that the zkDHT client expects,
 * bridging to the Rust DHT implementation in lib-network.
 */

class ZhtpDhtApi {
    constructor() {
        this.dhtClient = null;
        this.isInitialized = false;
        console.log(' DHT API: Initialized with HTTP endpoint connection');
    }

    async initialize(identity) {
        console.log('Initializing ZHTP DHT API bridge...');
        
        try {
            // Initialize DHT client through ZHTP API HTTP endpoint
            const response = await fetch('/api/v1/dht/initialize', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    identity: identity
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            if (result.success) {
                this.isInitialized = true;
                console.log('ZHTP DHT API bridge initialized successfully');
                return true;
            } else {
                throw new Error(result.message || 'Unknown initialization error');
            }
            
        } catch (error) {
            console.error('Failed to initialize DHT API bridge:', error);
            return false;
        }
    }

    async connectToPeer(peerAddress) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`DHT API: Connecting to peer ${peerAddress}`);
        
        try {
            const response = await fetch('/api/v1/dht/connect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    peer_address: peerAddress
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            if (result.success) {
                console.log(`DHT API: Connected to peer ${peerAddress}`);
                return true;
            } else {
                throw new Error(result.message || 'Connection failed');
            }
        } catch (error) {
            console.error(`DHT API: Failed to connect to peer ${peerAddress}:`, error);
            throw error;
        }
    }

    async discoverPeers(region = null, capabilities = []) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log('DHT API: Discovering peers...');
        
        try {
            const response = await fetch('/api/v1/dht/peers', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log(`DHT API: Discovered ${result.peers.length} peers`);
            return result.peers;
        } catch (error) {
            console.error('DHT API: Peer discovery failed:', error);
            return [];
        }
    }

    async fetchFromPeer(peerAddress, contentHash) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`DHT API: Fetching content ${contentHash.substring(0, 16)}... from peer ${peerAddress}`);
        
        try {
            const response = await fetch(`/api/v1/dht/content/${contentHash}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Peer-Address': peerAddress
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log(`DHT API: Fetched ${result.content.length} bytes from peer`);
            return result.content;
        } catch (error) {
            console.error(`DHT API: Failed to fetch from peer ${peerAddress}:`, error);
            throw error;
        }
    }

    async sendDHTQuery(peerAddress, query) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(` DHT API: Sending query to peer ${peerAddress}`);
        
        try {
            const response = await fetch('/api/v1/dht/query', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Peer-Address': peerAddress
                },
                body: JSON.stringify({
                    query: query,
                    peer_address: peerAddress
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log(`DHT API: Received response from peer ${peerAddress}`);
            return result;
        } catch (error) {
            console.error(`DHT API: Query failed to peer ${peerAddress}:`, error);
            throw error;
        }
    }

    async storeContent(domain, path, content) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(` DHT API: Storing content for ${domain}${path}`);
        
        try {
            const response = await fetch('/api/v1/dht/store', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    domain: domain,
                    path: path,
                    content: content
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log(`DHT API: Content stored with hash ${result.content_hash}`);
            return result.content_hash;
        } catch (error) {
            console.error(`DHT API: Failed to store content for ${domain}${path}:`, error);
            throw error;
        }
    }

    async resolveContent(domain, path) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`DHT API: Resolving content for ${domain}${path}`);
        
        try {
            const response = await fetch('/api/v1/dht/resolve', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    domain: domain,
                    path: path
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log(`DHT API: Content resolved to hash ${result.content_hash}`);
            return result.content_hash;
        } catch (error) {
            console.error(`DHT API: Failed to resolve content for ${domain}${path}:`, error);
            throw error;
        }
    }

    async fetchContent(contentHash) {
        if (!this.isInitialized) {
            throw new Error('DHT API not initialized');
        }

        console.log(`DHT API: Fetching content ${contentHash.substring(0, 16)}...`);
        
        try {
            const response = await fetch(`/api/v1/dht/content/${contentHash}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log(`DHT API: Fetched ${result.content.length} bytes`);
            return result.content;
        } catch (error) {
            console.error(`DHT API: Failed to fetch content ${contentHash}:`, error);
            throw error;
        }
    }

    async getStatistics() {
        if (!this.isInitialized) {
            return {
                totalPeers: 0,
                connectedPeers: 0,
                contentItems: 0,
                totalQueries: 0
            };
        }

        try {
            const response = await fetch('/api/v1/dht/statistics', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            return {
                totalPeers: result.total_peers,
                connectedPeers: result.connected_peers,
                contentItems: result.content_items,
                totalQueries: result.total_queries,
                averageResponseTime: result.average_response_time,
                cacheHitRate: result.cache_hit_rate
            };
        } catch (error) {
            console.error('DHT API: Failed to get statistics:', error);
            return {
                totalPeers: 0,
                connectedPeers: 0,
                contentItems: 0,
                totalQueries: 0
            };
        }
    }

    async getNetworkStatus() {
        if (!this.isInitialized) {
            return {
                connected: false,
                peerCount: 0,
                cacheSize: 0
            };
        }

        try {
            const response = await fetch('/api/v1/dht/status', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            return {
                connected: result.connected,
                peerCount: result.peer_count,
                cacheSize: result.cache_size,
                storageAvailable: result.storage_available,
                networkHealth: result.network_health
            };
        } catch (error) {
            console.error('DHT API: Failed to get network status:', error);
            return {
                connected: false,
                peerCount: 0,
                cacheSize: 0
            };
        }
    }
}

export default ZhtpDhtApi;
