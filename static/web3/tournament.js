window.onload = async function () {
    const abi = [
        {
            "anonymous": false,
            "inputs": [
                {
                    "indexed": false,
                    "internalType": "uint256",
                    "name": "tournamentId",
                    "type": "uint256"
                },
                {
                    "indexed": false,
                    "internalType": "uint256",
                    "name": "matchId",
                    "type": "uint256"
                },
                {
                    "indexed": false,
                    "internalType": "uint256",
                    "name": "team1Score",
                    "type": "uint256"
                },
                {
                    "indexed": false,
                    "internalType": "uint256",
                    "name": "team2Score",
                    "type": "uint256"
                }
            ],
            "name": "MatchScoreUpdated",
            "type": "event"
        },
        {
            "anonymous": false,
            "inputs": [
                {
                    "indexed": false,
                    "internalType": "uint256",
                    "name": "tournamentId",
                    "type": "uint256"
                },
                {
                    "indexed": false,
                    "internalType": "uint256[]",
                    "name": "matchIds",
                    "type": "uint256[]"
                }
            ],
            "name": "TournamentCreated",
            "type": "event"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "_tournamentId",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256[]",
                    "name": "_matchIds",
                    "type": "uint256[]"
                }
            ],
            "name": "createTournament",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "_tournamentId",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256",
                    "name": "_matchId",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256",
                    "name": "_team1Score",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256",
                    "name": "_team2Score",
                    "type": "uint256"
                }
            ],
            "name": "updateMatchScore",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "_tournamentId",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256",
                    "name": "_matchId",
                    "type": "uint256"
                }
            ],
            "name": "getMatchScore",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                },
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                },
                {
                    "internalType": "bool",
                    "name": "",
                    "type": "bool"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "_tournamentId",
                    "type": "uint256"
                }
            ],
            "name": "getTournamentInfo",
            "outputs": [
                {
                    "internalType": "string",
                    "name": "",
                    "type": "string"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ];

    const contractAddress = "0x02c70D25D48DAe6D657F11e5F7f875d513CE5d84";
    const senderAddress = "0xBe8D4b146a9012444d467223D39cc93a17018158";

    // Fallback to a local Ganache node
    web3 = new Web3(new Web3.providers.HttpProvider("http://localhost:7545"));
    const instance = new web3.eth.Contract(abi, contractAddress);

    try {
        // await instance.methods.createTournament(2, [1, 2, 3]).send({ from: senderAddress, gas: 1000000 });
        await instance.methods.updateMatchScore(2, 1, 5, 4).send({ from: senderAddress, gas: 1000000 });
        let result = await instance.methods.getTournamentInfo(2).call();
        console.log("Match score is:", result);
    } catch (error) {
        console.log("Error:", error)
    }
}

// 1. Load blockchain with account
// 2. export functions