// const roomName = JSON.parse(document.getElementById('room-name').textContent);
var onlineusers;
global.chat.blocklist = [];

import { global } from '../game/global.js';

function getCookie(name) {
    let value = `; ${document.cookie}`;
    let parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }


const sortAlphaNum = (a, b) => a.localeCompare(b, 'en', { numeric: true })
function MySort(alphabet)
{
    return function(a, b) {
        var index_a = alphabet.indexOf(a[0]),
        index_b = alphabet.indexOf(b[0]);

        if (index_a === index_b) {
            // same first character, sort regular
            if (a < b) {
                return -1;
            } else if (a > b) {
                return 1;
            }
            return 0;
        } else {
            return index_a - index_b;
        }
    }
}

var sortSpeacialChar = MySort('*!@_.()#^&%-=+01234567989abcdefghijklmnopqrstuvwxyz');

class ChatSocketManager {
    constructor() {
        this.socketList = [];
    }

    // Register the socket and room name to an array
    registerSocket(roomname, socket) {
        this.socketList.push({roomname, socket});
    }

    // delete from list and close socket
    closeSocket(roomname) {
        let index = this.socketList.findIndex(roomSocket => roomSocket.roomname === roomname);
        const roomSocket = this.socketList.find(roomSocket => roomSocket.roomname === roomname);
        roomSocket.socket.close();
        if (index > -1) { // only splice array when item is found
            this.socketList.splice(index, 1); // 2nd parameter means remove one item only
          }
    }

    // Only delete from list (Note*) Might be better to seperate close sockt and delete entry.
    // Delete entry to be placed in socket.onclose() while close socket can be used whenever
    deleteEntry(roomname) {
        let index = this.socketList.findIndex(roomSocket => roomSocket.roomname === roomname);
        if (index > -1) { // only splice array when item is found
            this.socketList.splice(index, 1); // 2nd parameter means remove one item only
          }
    }
    
    // Returns all existing roomname
    getAllSockets() {
        return this.socketList.map(entry => entry.roomname);
    }

    //returns the socket associated with the roomname
    getSocket(roomname) {
        const roomSocket = this.socketList.find(roomSocket => roomSocket.roomname === roomname);
        return roomSocket ? roomSocket.socket : null;
    }
}

// Initiate socket manager
const chatSocketManager = new ChatSocketManager

const lobby = 'ws://'
+ window.location.host
+ '/ws/chat/lobby/';

function createChatSocket(room) {
    global.chat.currentGameChatSocket = new WebSocket(room);
    console.log("connected to:", room, currentChatRoomSocket);
};

// Function reuses currentChatRoomSocket to move betwwen game chat
function enterChatRoom(room) {
    createChatSocket(room);
    global.chat.currentGameChatSocket.onmessage = function(e) {
        const data = JSON.parse(e.data);
        console.log(data);
        if (data["type"] == "msg") {
            // if (!blocklist.includes(""))
            const paramsg = document.createElement("p");
            paramsg.style.textAlign = "left";
            paramsg.innerText = data["username"] + ":   " + data["message"];
            let msgContainer = document.querySelector('#chat-msg');
            msgContainer.appendChild(paramsg);
        }
    };
    
    global.chat.currentGameChatSocket.onclose = function(e) {
        console.error('Chat socket closed unexpectedly');
    };

    global.chat.currentGameChatSocket.onerror = function(e) {
        console.error('Chat socket encounter error');
    };
};

// To exit currentChatRoom socket. Must be run when ever exit game and logout
function exitChatRoom() {
    global.chat.currentGameChatSocket.close();
};

// Function used solely to enter lobby and is run after login
function enterLobby() {
    // retrieveBlockList(global.gameplay.username );
    global.chat.chatLobbySocket =  new WebSocket(lobby);
    global.chat.chatLobbySocket.onmessage = function(e) {
        const data = JSON.parse(e.data);
        console.log(data);
        if (data["type"] == "msg") {
            if (!global.chat.blocklist.includes(data["username"])) {
                let paramsg = document.createElement("p");
                paramsg.style.textAlign = "left";
                paramsg.innerText = data["username"] + ":\n" + data["message"];
                let msgContainer = document.createElement('div');
                msgContainer.appendChild(paramsg);
                let chatContainer = document.querySelector('.chat-msg');
                chatContainer.appendChild(msgContainer);
            }
        } else if (data["type"] == "userlist") {
            console.log("current online users:", data["onlineUsers"])
            onlineusers = data["onlineUsers"];
            updateLobbyList(onlineusers)
        } else if (data["type"] == "pm") {
            acceptPrivateMessage(data);
        }
    };
    
    global.chat.chatLobbySocket.onclose = function(e) {
        const paramsg = document.createElement("p");
        paramsg.style.textAlign = "left";
        paramsg.style.color = "red";
        paramsg.innerText = "You have disconnected from lobby chat server"
        let msgContainer = document.querySelector('#chat-msg');
        msgContainer.appendChild(paramsg);
        console.error('Chat socket closed unexpectedly');
    };

    global.chat.chatLobbySocket.onerror = function(e) {
        const paramsg = document.createElement("p");
        paramsg.style.textAlign = "left";
        paramsg.style.color = "red";
        paramsg.innerText = "You have encounter an error on lobby chat server"
        let msgContainer = document.querySelector('#chat-msg');
        console.error('Chat socket encounter error');
    };
};

// To exit currentChatRoom socket. Must be run when ever exit game and logout
function exitLobby() {
    lobbySocket.close();
};

// function updateLobbyList(data) {
//     let lobbyList = document.getElementById("Lobby-list")
//     let listdiv = document.createElement("div");
//     data.forEach(user => {
//         let p = document.createElement("p");
//         p.classList.add("chat-options");
//         p.classList.add(user);
//         p.innerText = user;
//         let profileBtn = document.createElement("button");
//         profileBtn.classList.add("chat-options-profile");
//         profileBtn.classList.add(user);
//         profileBtn.innerHTML = '  <i class="fa-solid fa-user"></i>'
//         p.appendChild(profileBtn);
//         let messageBtn = document.createElement("button");
//         messageBtn.classList.add("chat-options-message");
//         messageBtn.classList.add(user);
//         messageBtn.innerHTML = '  <i class="fa-solid fa-comment"></i>'
//         messageBtn.addEventListener('click', createPrivateMessage);
//         p.appendChild(messageBtn);
//         listdiv.appendChild(p);
//     });
//     if (lobbyList.childElementCount > 0)
//         lobbyList.replaceChildren(listdiv)
// }

function updateLobbyList(data) {
    let lobbyList = document.getElementById("Lobby-list")
    let listdiv = document.createElement("div");
    data.forEach(user => {
        let p = document.createElement("p");
        p.classList.add("chat-options");
        p.classList.add(user);
        p.innerText = user;
        if (user != global.gameplay.username) {
            let profileBtn = document.createElement("button");
            if (global.chat.blocklist.includes(user) ) {
                console.log(user, " is in block list")
                profileBtn.classList.add("chat-options-profile");
                profileBtn.classList.add(user);
                profileBtn.innerHTML = '  <i class="fa-solid fa-user-slash"></i>'
                profileBtn.addEventListener("click", unblockUser)
                p.appendChild(profileBtn);
            } else {
                console.log(user, global.chat.blocklist.includes(user)," is not in block list")
                profileBtn.classList.add("chat-options-profile");
                profileBtn.classList.add(user);
                profileBtn.innerHTML = '  <i class="fa-solid fa-user-xmark"></i>'
                profileBtn.addEventListener("click", blockUser)
                p.appendChild(profileBtn);
            }
            let messageBtn = document.createElement("button");
            messageBtn.classList.add("chat-options-message");
            messageBtn.classList.add(user);
            messageBtn.innerHTML = '  <i class="fa-solid fa-comment"></i>'
            messageBtn.addEventListener('click', createPrivateMessage);
            p.appendChild(messageBtn);
        }
        listdiv.appendChild(p);
    });
    if (lobbyList.childElementCount > 0)
        lobbyList.replaceChildren(listdiv)
}
function createPrivateMessage(e){
    const name = []
    let sender = global.gameplay.username;
    let receiver = e.target.classList[1];
    name.push(sender);
    name.push(receiver);
    name.sort(sortSpeacialChar)
    let roomname = name[0] + '_' + name[1];
    let tab;
    console.log("create PM Sender:", sender);
    console.log("create PM Receiver:", receiver);
    console.log(roomname);

    if(receiver != global.gameplay.username) {
        if (tab = document.querySelector(".chat-tab."  + roomname)) {
            tab.click();
            console.log(roomname, "chat already exist");

        } else {
            let friendChat = document.createElement("div");
            friendChat.classList.add("chat-tab");
            friendChat.classList.add(roomname);
            friendChat.innerText = receiver;
            let closeBtn = document.createElement('i');
            closeBtn.classList.add("friend-close-button");
            closeBtn.classList.add(roomname);
            closeBtn.classList.add("fa");
            closeBtn.classList.add("fa-xmark");
            closeBtn.addEventListener("click", exitPrivateChat)
            friendChat.appendChild(closeBtn);
            // let tabs = document.querySelector(".tab");
            let tabs = document.querySelector(".lobby-friend");
            tabs.insertBefore(friendChat, tabs.firstChild);
            friendChat.addEventListener("click", privateMessageTab)
            let chatcontainer = document.querySelector(".display-chat-container");
            let privateChatContainer = document.createElement("div");
            privateChatContainer.classList.add("p-chat-container");
            privateChatContainer.classList.add(roomname);
            privateChatContainer.classList.add("display-none");
            let privateChatLog = document.createElement("div");
            privateChatLog.classList.add("p-chat-log");
            privateChatLog.classList.add(roomname);
            let privateChatMsg = document.createElement("div");
            privateChatMsg.classList.add("p-chat-msg");
            privateChatMsg.classList.add(roomname);
            privateChatLog.appendChild(privateChatMsg);
            privateChatContainer.appendChild(privateChatLog);
            let inputsubmit = document.createElement("div");
            inputsubmit.classList.add("p-message-box");
            inputsubmit.classList.add(roomname);
            inputsubmit.classList.add("display-none");
            let privateChatInput = document.createElement("input");
            privateChatInput.classList.add("p-chat-input");
            privateChatInput.classList.add(roomname);
            privateChatInput.setAttribute('type', 'text');
            privateChatInput.setAttribute('placeholder', 'Type message...');
            privateChatInput.setAttribute('maxlength', '100');
            privateChatInput.addEventListener("keyup", SendPrivateMessageKey)
            inputsubmit.appendChild(privateChatInput);
            let privateChatSubmit = document.createElement("input");
            privateChatSubmit.classList.add("p-chat-submit");
            privateChatSubmit.classList.add(roomname);
            privateChatSubmit.setAttribute('type', 'button');
            privateChatSubmit.setAttribute('value', 'Send');
            privateChatSubmit.setAttribute('style', "align: right;");
            privateChatSubmit.addEventListener("click", SendPrivateMessage)
            inputsubmit.appendChild(privateChatSubmit);
            chatcontainer.appendChild(privateChatContainer);
            chatcontainer.appendChild(inputsubmit);

            global.chat.chatLobbySocket.send(JSON.stringify({
                'type': 'pm',
                'sender': sender,
                'receiver': receiver
            }));
            let socket = new WebSocket('ws://'
            + window.location.host
            + '/ws/pm/' + roomname + '/')
            socket.onmessage = function(e) {
                const data = JSON.parse(e.data);
                console.log(data);
                if (data["type"] == "msg") {
                    const paramsg = document.createElement("p");
                    paramsg.style.textAlign = "left";
                    paramsg.innerText = data["username"] + ":   " + data["message"];
                    let msgContainer = document.querySelector('.p-chat-msg.' + roomname);
                    msgContainer.appendChild(paramsg);
                };
            };
            
            socket.onclose = function(e) {
                // const paramsg = document.createElement("p");
                // paramsg.style.textAlign = "left";
                // paramsg.style.color = "red";
                // paramsg.innerText = "You have disconnected"
                // let msgContainer = document.querySelector('.p-chat-msg.' + roomname);
                // msgContainer.appendChild(paramsg);
                console.log('Chat socket', roomname, 'closed');
            };
            
            socket.onerror = function(e) {
                // const paramsg = document.createElement("p");
                // paramsg.style.textAlign = "left";
                // paramsg.style.color = "red";
                // paramsg.innerText = "You have encounter an error."
                // let msgContainer = document.querySelector('.p-chat-msg.' + roomname);
                console.error('Chat socket encounter error');
            };
            chatSocketManager.registerSocket(roomname, socket);
        }
    }
};

function acceptPrivateMessage(data){
    let sender = data["sender"];
    let receiver = data["receiver"];

    if (!global.chat.blocklist.includes(sender)) {
        const name = [];
        name.push(sender);
        name.push(receiver);
        name.sort(sortSpeacialChar)
        let roomname = name[0] + '_' + name[1];
    
        console.log(roomname);
        if(receiver == global.gameplay.username) {
            if (document.querySelector(".chat-tab."  + roomname)) {
                console.log(roomname, "chat already exist");
    
            } else {
                let socket = new WebSocket('ws://'
                + window.location.host
                + '/ws/pm/' + roomname + '/')
    
                socket.onmessage = function(e) {
                    const data = JSON.parse(e.data);
                    console.log(data);
                    if (data["type"] == "msg") {
                        const paramsg = document.createElement("p");
                        paramsg.style.textAlign = "left";
                        paramsg.innerText = data["username"] + ":   " + data["message"];
                        let msgContainer = document.querySelector('.p-chat-msg.' + roomname);
                        msgContainer.appendChild(paramsg);
                    };
                };
                
                socket.onclose = function(e) {
                    console.error('Chat socket closed unexpectedly');
                };
                
                socket.onerror = function(e) {
                    console.error('Chat socket encounter error');
                };
    
                chatSocketManager.registerSocket(roomname, socket);
                let friendChat = document.createElement("div");
                friendChat.classList.add("chat-tab");
                friendChat.classList.add(roomname);
                friendChat.innerText = sender;
                let closeBtn = document.createElement('i');
                closeBtn.classList.add("friend-close-button");
                closeBtn.classList.add(roomname);
                closeBtn.classList.add("fa");
                closeBtn.classList.add("fa-xmark");
                closeBtn.addEventListener("click", exitPrivateChat)
                friendChat.appendChild(closeBtn);
                // tabs = document.querySelector(".tab");
                // tabs.appendChild(friendChat);
                let tabs = document.querySelector(".lobby-friend");
                tabs.insertBefore(friendChat, tabs.firstChild);
                friendChat.addEventListener("click", privateMessageTab)    
                let chatcontainer = document.querySelector(".display-chat-container");
                let privateChatContainer = document.createElement("div");
                privateChatContainer.classList.add("p-chat-container");
                privateChatContainer.classList.add(roomname);
                privateChatContainer.classList.add("display-none");
                let privateChatLog = document.createElement("div");
                privateChatLog.classList.add("p-chat-log");
                privateChatLog.classList.add(roomname);
                let privateChatMsg = document.createElement("div");
                privateChatMsg.classList.add("p-chat-msg");
                privateChatMsg.classList.add(roomname);
                privateChatLog.appendChild(privateChatMsg);
                privateChatContainer.appendChild(privateChatLog);
                let inputsubmit = document.createElement("div");
                inputsubmit.classList.add("p-message-box");
                inputsubmit.classList.add(roomname);
                inputsubmit.classList.add("display-none");
                let privateChatInput = document.createElement("input");
                privateChatInput.classList.add("p-chat-input");
                privateChatInput.classList.add(roomname);
                privateChatInput.setAttribute('type', 'text');
                privateChatInput.setAttribute('placeholder', 'Type message...');
                privateChatInput.setAttribute('maxlength', '100');
                privateChatInput.addEventListener("keyup", SendPrivateMessageKey)
                inputsubmit.appendChild(privateChatInput);
                let privateChatSubmit = document.createElement("input");
                privateChatSubmit.classList.add("p-chat-submit");
                privateChatSubmit.classList.add(roomname);
                privateChatSubmit.setAttribute('type', 'button');
                privateChatSubmit.setAttribute('value', 'Send');
                privateChatSubmit.setAttribute('style', "align: right;");
                privateChatSubmit.addEventListener("click", SendPrivateMessage)
                inputsubmit.appendChild(privateChatSubmit);
                chatcontainer.appendChild(privateChatContainer);
                chatcontainer.appendChild(inputsubmit);
            }
        }
    }
};

function privateMessageTab(e) {
    // Declare all variables
    var i, tabcontent, tablinks, roomname, chattabs, pchat;

    roomname = e.target.classList[1];
    // Get all elements with class="tabcontent" and hide them
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        // tabcontent[i].style.display = "none";
        tabcontent[i].classList.add("display-none");
    }
    // Get all elements with class="tablinks" and remove the class "active"
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].classList.remove("active");
    }
    
    // Get all elements with class="chat-tab" and hide them
    chattabs = document.getElementsByClassName("chat-tab");
    for (i = 0; i < chattabs.length; i++) {
        chattabs[i].classList.remove("active");
    }
    
    e.target.classList.add("active");
    // document.getElementById("lobby-container").style.display = "none";
    document.getElementById("lobby-container").classList.add("display-none");
    document.getElementById("message-box").classList.add("display-none");

    // if (document.querySelector('.p-chat-container.' + roomname)) {
    //     // document.querySelector('.p-chat-container.' + roomname).style.display = "block";
    //     document.querySelector('.p-chat-container.' + roomname).classList.remove("display-none");
    // }

    // Get all elements with class="roomname" and show them
    pchat = document.getElementsByClassName(roomname);
    for (i = 0; i < pchat.length; i++) {
        pchat[i].classList.remove("display-none");
    }

}

function SendPrivateMessage(e) {
    let roomname = e.target.classList[1];

    const messageInputDom = document.querySelector(".p-chat-input." + roomname);
    let message = messageInputDom.value;
    if (typeof message === "string" && message.trim().length > 0) {
        let roomsocket = chatSocketManager.getSocket(roomname)
        roomsocket.send(JSON.stringify({
            'type': 'msg',
            'username': global.gameplay.username,
            'message': message
        }));
    }
    messageInputDom.value = '';
};

function SendPrivateMessageKey(e) {
    let roomname = e.target.classList[1];
    // document.querySelector(".p-chat-submit." + roomname).focus();
    if (e.key === 'Enter') {
        document.querySelector(".p-chat-submit." + roomname).click();
    }
};

function exitPrivateChat(e) {
    let roomname = e.target.classList[1];
    // Close socket first before delete chat 
    chatSocketManager.closeSocket(roomname);
    // Get all elements with class="tabcontent" and hide them
    let privateChat = document.getElementsByClassName(roomname);
    while (privateChat.length > 0) {
        privateChat[0].parentNode.removeChild(privateChat[0]);
    }
    // document.getElementById("Lobby-tab").click();
}

document.querySelector('#lobby-chat-message-submit').onclick = function(e) {
    const messageInputDom = document.querySelector('#lobby-chat-message-input');
    let message = messageInputDom.value;
    if (typeof message === "string" && message.trim().length > 0) {
        global.chat.chatLobbySocket.send(JSON.stringify({
            'type': 'msg',
            'username': global.gameplay.username,
            'message': message
        }));
    }
    messageInputDom.value = '';
};

document.querySelector('#lobby-chat-message-input').focus();
document.querySelector('#lobby-chat-message-input').onkeyup = function(e) {
    if (e.key === 'Enter') {  // enter, return
        document.querySelector('#lobby-chat-message-submit').click();
    }
};

// document.querySelector('#room-chat-message-submit').onclick = function(e) {
//     const messageInputDom = document.querySelector('#room-chat-message-input');
//     let message = messageInputDom.value;
//     if (typeof message === "string" && message.trim().length != 0)
//         currentChatRoomSocket.send(JSON.stringify({
//             'type': 'msg',
//             'username': document.global.gameplay.username,
//             'message': message
//         }));
//     messageInputDom.value = '';
// };

// document.querySelector('#room-chat-message-input').focus();
// document.querySelector('#room-chat-message-input').onkeyup = function(e) {
//     if (e.key === 'Enter') {  // enter, return
//         document.querySelector('#room-chat-message-submit').click();
//     }
// };

// const chatSocket = new WebSocket(
//     'ws://'
//     + window.location.host
//     + '/ws/chat/'
//     + roomName
//     + '/'
// );
document.getElementById("Lobby-tab").addEventListener("click", setActive)
document.getElementById("Friend-tab").addEventListener("click", setActive)
function setActive(e){
    // console.log(e.target);
    if (e.target.classList[1] === "active") {
        // console.log(e.target.className);
        e.target.classList.remove("active");
        if (e.target.id === "Lobby-tab"){
            document.getElementById("Lobby-list").classList.add("display-none");
        } else {
            document.getElementById("Friend-list").classList.add("display-none");
        }
        document.querySelector(".chat-log").classList.remove("partial-grid");
        document.querySelector(".chat-log").classList.add("full-grid");
    } else {
        var i, tabcontent, tablinks, chattabs, privatechattab, privatechatiput;
  
        // Get all elements with class="tabcontent" and hide them
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].classList.add("display-none");
        }
    
        // Get all elements with class="tablinks" and remove the class "active"
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
        }

        // Get all elements with class="chat-tab" and hide them
        chattabs = document.getElementsByClassName("chat-tab");
        for (i = 0; i < chattabs.length; i++) {
            chattabs[i].className = chattabs[i].className.replace(" active", "");
        }
        
        // Get all elements with class="p-chat-container" and hide them
        privatechattab = document.getElementsByClassName("p-chat-container");
        for (i = 0; i < privatechattab.length; i++) {
            privatechattab[i].classList.add("display-none");
        }

        privatechatiput = document.getElementsByClassName("p-message-box");
        for (i = 0; i < privatechatiput.length; i++) {
            privatechatiput[i].classList.add("display-none");
        }

        // Show the current tab, and add an "active" class to the button that opened the tab
        if (e.target.id === "Lobby-tab"){
            document.getElementById("Lobby-list").classList.remove("display-none");
        } else {
            document.getElementById("Friend-list").classList.remove("display-none");
        }
        e.target.classList.add("active");
        document.getElementById("lobby-container").classList.remove("display-none");
        document.getElementById("message-box").classList.remove("display-none");
        document.querySelector(".chat-log").classList.remove("full-grid");
        document.querySelector(".chat-log").classList.add("partial-grid");
    }
}

function openTab(evt, tabs) {
    // Declare all variables
    var i, tabcontent, tablinks;
  
    // Get all elements with class="tabcontent" and hide them
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
      tabcontent[i].classList.add("display-none");
    }
  
    // Get all elements with class="tablinks" and remove the class "active"
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
      tablinks[i].className = tablinks[i].className.replace(" active", "");
    }

    // Get all elements with class="chat-tab" and hide them
    chattabs = document.getElementsByClassName("chat-tab");
    for (i = 0; i < chattabs.length; i++) {
        chattabs[i].className = chattabs[i].className.replace(" active", "");
    }
    
    // Get all elements with class="p-chat-container" and hide them
    privatechats = document.getElementsByClassName("p-chat-container");
    for (i = 0; i < privatechats.length; i++) {
        privatechats[i].classList.add("display-none");
    }

    // Show the current tab, and add an "active" class to the button that opened the tab
    document.getElementById(tabs).classList.remove("display-none");
    evt.currentTarget.className += " active";

    document.getElementById("lobby-container").classList.remove("display-none");
}

//Should be run once when logged in. Argument with username will be implemented for multiuse
function retrieveBlockList(username) {
    let url = 'http://127.0.0.1:8000/chat/blocklist/' + username + "/";
    console.log('retrieveBlockList URL:', url);
    fetch(url)
        .then(response => {
            // Handle response you get from the API
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            global.chat.blocklist = data['blocklist'];
            console.log('global block list in retrieve', global.chat.blocklist);
            enterLobby();
        })
        .catch(error => {
            console.error('Error', error);
        });
}

// Use api to add user to block list
function blockUser(e) {
    let username = e.target.classList[1];
    let url = 'http://127.0.0.1:8000/chat/blocklist/' + global.gameplay.username + '/';

    global.chat.blocklist.push(username);
    // list = blocklist.map(x => ({animal: x}));
    let formData = {
        blocklist: global.chat.blocklist
    };

    let fetchData = {
        method: 'PUT',
        headers: new Headers({
            'Content-Type': 'application/json',
            'X-CSRFTOKEN': getCookie("csrftoken")
        }),
        body: JSON.stringify(formData)
    }

    fetch(url, fetchData)
        .then(response => {
            // Handle response you get from the API
            if (!response.ok) {
                console.log(response)
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Process the retrieved user data
            console.log('Data:', data);
            global.chat.blocklist = data['blocklist']
            console.log('global.chat.blocklist in block user:', global.chat.blocklist);
            let profileBtn = document.createElement("button");
            profileBtn.classList.add("chat-options-profile");
            profileBtn.classList.add(username);
            profileBtn.innerHTML = '  <i class="fa-solid fa-user-slash"></i>';
            profileBtn.addEventListener("click", unblockUser);
            e.target.replaceWith(profileBtn);
        })
        .catch(error => {
            console.error('Error', error);
        });
}

// Use api to add user to block list
function unblockUser(e) {
    let username = e.target.classList[1];
    let url = 'http://127.0.0.1:8000/chat/blocklist/' + global.gameplay.username + '/';

    let index = global.chat.blocklist.findIndex(user => user === username);
    if (index > -1) { // only splice array when item is found
        global.chat.blocklist.splice(index, 1);
    }

    let formData = {
        blocklist: global.chat.blocklist
    };


    let fetchData = {
        method: 'PUT',
        headers: new Headers({
            'Content-Type': 'application/json; charset=UTF-8',
            'X-CSRFTOKEN': getCookie("csrftoken")
        }),
        body: JSON.stringify(formData)
    }

    fetch(url, fetchData)
        .then(response => {
            // Handle response you get from the API
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Process the retrieved user data
            console.log('Data:', data);
            global.chat.blocklist = data['blocklist']
            console.log('global.chat.blocklist in unblock user:', global.chat.blocklist);
            let profileBtn = document.createElement("button");
            profileBtn.classList.add("chat-options-profile");
            profileBtn.classList.add(username);
            profileBtn.innerHTML = '  <i class="fa-solid fa-user-xmark"></i>';
            profileBtn.addEventListener("click", blockUser);
            e.target.replaceWith(profileBtn);
        })
        .catch(error => {
            console.error('Error', error);
        });
}

// Create a dropdown menu for profile, add ban unban to options
function createProfileDropDown(username) {
    let optionsContainer = document.createElement("div");
    optionsContainer.setAttribute("id", "profile-dropdown");
    optionsContainer.classList.add("profile-dropdown");
    let dropDownBtn = document.createElement("button")
    dropDownBtn.innerText = "Options"
    dropDownBtn.classList.add("dropdown-btn");
    // Will change formatting
    dropDownBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        toggleDropdown();
    });
    let dropDownIcon = document.createElement("i");
    dropDownIcon.classList.add("fa-solid");
    dropDownIcon.classList.add("fa-chevron-up");
    dropDownIcon.setAttribute("id", "arrow");
    dropDownBtn.appendChild(dropDownIcon);
    if (global.chat.blocklist.includes(username) ) {
        let unblock = document.createElement("a")
        unblock.setAttribute("href", "#unblock")
        let unblockIcon = document.createElement("i");
        unblockIcon.classList.add("fa-solid");
        unblockIcon.classList.add("fa-o");
        unblock.classList.add(username);
        unblock.addEventListener("click", unblockUser)
        unblock.appendChild(unblockIcon);
        unblock.innerHTML += "Unblock";
        optionsContainer.appendChild(unblock);
    } else {
        let block = document.createElement("a")
        block.setAttribute("href", "#block")
        let blockIcon = document.createElement("i");
        blockIcon.classList.add("fa-solid");
        blockIcon.classList.add("fa-x");
        block.classList.add(username);
        block.addEventListener("click", blockUser)
        block.appendChild(blockIcon);
        block.innerHTML += "Block";
        optionsContainer.appendChild(block);
    }
    // Testing dropdown. Production will be on another class
    document.querySelector(".profile-test").appendChild(dropDownBtn);
    document.querySelector(".profile-test").appendChild(optionsContainer);
}

const toggleDropdown = function () {
    document.getElementById("profile-dropdown").classList.toggle("show");
    document.getElementById("arrow").classList.toggle("arrow");
  };


// Function should be executed after login
// During logout, exitLobby should be executed
document.addEventListener("DOMContentLoaded", function() {
    // Code that interacts with the DOM, including openTab function
    
});
/////////////////////////////////////////////////////////////
// Please check multiplayer.js for the temporary solution
// console.log("current user is",  global.gameplay.username);
// enterLobby();
// retrieveBlockList("itsuki");


export {retrieveBlockList, enterLobby, exitLobby, enterChatRoom, exitChatRoom}