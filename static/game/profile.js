import { global } from './global.js';
import { windowResize } from './main.js';
import { getCookie } from './login-utils.js';

function keyBindingProfile() {
	document.addEventListener("click", (e)=>{
		document.querySelector(".profile-error").textContent = "";
		document.querySelector(".profile-error").classList.add("display-none");
	})
	const profileExpand = document.querySelector(".profile-expand");
	profileExpand.addEventListener("click", (e)=>{
		if (!global.ui.profile) {
			global.ui.profile = 1;
			global.ui.chat = 0;
			windowResize();
		}
	})
	document.querySelector(".nickname-submit").addEventListener("submit", e=>{
		e.preventDefault();
		document.querySelector(".profile-error").textContent = "";
		document.querySelector(".profile-error").classList.add("display-none");
		change_nickname();
	})
	document.querySelector(".img-upload").addEventListener("submit", e=>{
		e.preventDefault();
		document.querySelector(".profile-error").textContent = "";
		document.querySelector(".profile-error").classList.add("display-none");
		change_profile_image();
	})
	document.querySelector(".profile-refresh").addEventListener("click", e=>{
		e.stopPropagation();
		fetch_profile();
		fetch_matchHistory();
		document.querySelector(".profile-error").textContent = "Profile refreshed";
		document.querySelector(".profile-error").classList.remove("display-none");
	})
}

async function fetch_profile(e) {
	if (global.ui.auth && global.gameplay.username) {
		try {
			const response = await fetch(global.fetch.profileURL + global.gameplay.username + '/', {
			method: 'GET',
			headers: {
				'X-CSRFToken': getCookie("csrftoken"),
			},
			});
			if (!response.ok) {
				document.querySelector(".profile-error").classList.remove("display-none");
				document.querySelector(".profile-error").textContent = "Server Error"
				global.gameplay.nickname = "";
				global.gameplay.imageURL = "";
				populateProfile();
			}
			else {
				const data = await response.json();
				global.gameplay.username = data.username
				global.gameplay.nickname = data.nick_name;
				global.gameplay.imageURL = data.image;
				populateProfile();
			}
		}
		catch (e) {
			document.querySelector(".profile-error").classList.remove("display-none");
			document.querySelector(".profile-error").textContent = "Server Error"
			global.gameplay.nickname = "";
			global.gameplay.imageURL = "";
			populateProfile();
		}
	}
	else {
		document.querySelector(".profile-error").classList.remove("display-none");
		document.querySelector(".profile-error").textContent = "User not logged in. Please login again."
	}
}

async function fetch_match_history_profile_pic(username) {
	console.log("here")
	try {
		const response = await fetch(global.fetch.profileURL + username + '/', {
		method: 'GET',
		headers: {
			'X-CSRFToken': getCookie("csrftoken"),
		},
		});
		if (response.ok) {
			const data = await response.json();
			const parentVersus = document.querySelector(".match-history-versus");
			const parentTournament = document.querySelector(".match-history-tournament");
			if (parentVersus.children.length !== 0) {
				document.querySelectorAll(".match-history-versus-button."+username).forEach(button=>{
					// button.getElementsByTagName('img')[0].src = "/";
					const timestamp = new Date().getTime(); 
					button.getElementsByTagName('img')[0].src = `${data.image}?timestamp=${timestamp}`;
					
				})
			}
			if (parentTournament.children.length !== 0) {
				document.querySelectorAll(".match-history-tournament-button."+username).forEach(button=>{
					// button.getElementsByTagName('img')[0].src = "/";
					const timestamp = new Date().getTime(); 
					button.getElementsByTagName('img')[0].src = `${data.image}?timestamp=${timestamp}`;
					
				})
			}
		}
	}
	catch (e) {
		pass;
	}
}


async function change_nickname(e) {
	if (global.ui.auth && global.gameplay.username) {
		try {
			const response = await fetch(global.fetch.profileURL + global.gameplay.username +'/', {
			method: 'PUT',
			headers: {
				'X-CSRFToken': getCookie("csrftoken"),
				'Content-Type':'application/json',
			},
			body: JSON.stringify({
				nick_name:document.getElementById("profile-nickname-input").value,
			}),
			});
			if (!response.ok) {
				document.querySelector(".profile-error").classList.remove("display-none");
				document.querySelector(".profile-error").textContent = "Server Error";
				global.gameplay.nickname = "";
				document.getElementById("profile-nickname-input").value = "";
			}
			else {
				const data = await response.json();
				global.gameplay.nickname = data.nick_name;
				document.getElementById("profile-nickname-input").value = global.gameplay.nickname;
				document.querySelector(".profile-error").classList.remove("display-none");
				document.querySelector(".profile-error").textContent = "Nickname changed"
			}
		}
		catch (e) {
			document.querySelector(".profile-error").classList.remove("display-none");
			document.querySelector(".profile-error").textContent = "Server Error";
			global.gameplay.nickname = "";
			document.getElementById("profile-nickname-input").value = "";
		}
	}
	else {
		document.querySelector(".profile-error").classList.remove("display-none");
		document.querySelector(".profile-error").textContent = "User not logged in. Please login again."
	}
}

async function change_profile_image(e) {
	const formData = new FormData();
	formData.append('image', document.getElementById("profile-img-upload").files[0]);
	if (global.ui.auth && global.gameplay.username) {
		try {
			const response = await fetch(global.fetch.profileURL + global.gameplay.username +'/', {
			method: 'PUT',
			headers: {
				'X-CSRFToken': getCookie("csrftoken"),
			},
			body: formData,
			});
			if (!response.ok) {
				document.querySelector(".profile-error").classList.remove("display-none");
				document.querySelector(".profile-error").textContent = "Server Error"
				global.gameplay.imageURL = "";
				document.querySelector(".profile-image").src = global.gameplay.imageURL;
			}
			else {
				let url = window.URL.createObjectURL(document.getElementById("profile-img-upload").files[0]);
				document.querySelector(".profile-image").src= url;
				document.querySelector(".profile-error").classList.remove("display-none");
				document.querySelector(".profile-error").textContent = "Profile image changed"
			}
		}
		catch (e) {
			document.querySelector(".profile-error").classList.remove("display-none");
			document.querySelector(".profile-error").textContent = "Server Error"
			global.gameplay.imageURL = "";
			document.querySelector(".profile-image").src = global.gameplay.imageURL;
		}
	}
	else {
		document.querySelector(".profile-error").classList.remove("display-none");
		document.querySelector(".profile-error").textContent = "User not logged in. Please login again."
	}
}

async function fetch_matchHistory(e) {
	if (global.ui.auth && global.gameplay.username) {
		try {
			const response = await fetch(global.fetch.matchHistoryURL + global.gameplay.username +'/', {
			method: 'GET',
			headers: {
				'X-CSRFToken': getCookie("csrftoken"),
			},
			});
			if (!response.ok) {
				document.querySelector(".profile-error").classList.remove("display-none");
				document.querySelector(".profile-error").textContent = "Server Error"
				document.querySelector(".profile-match-history").textContent = "";
			}
			else {
				const JSONdata = await response.json();
				populateMatchHistory(JSONdata)
			}
		}
		catch (e) {
			document.querySelector(".profile-error").classList.remove("display-none");
			document.querySelector(".profile-error").textContent = "Server Error"
			document.querySelector(".match-history-versus").textContent = "";
			document.querySelector(".match-history-tournament").textContent = "";
		}
	}
	else {
		document.querySelector(".profile-error").classList.remove("display-none");
		document.querySelector(".profile-error").textContent = "User not logged in. Please login again."
	}
}

function populateProfile() {
	document.querySelector(".profile-image").src = global.gameplay.imageURL;
	document.querySelector(".profile-username").textContent = global.gameplay.username;
	document.getElementById("profile-nickname-input").value = global.gameplay.nickname;
}

function populateMatchHistory(JSONdata) {
	const username_list=[];
	const parentVersus = document.querySelector(".match-history-versus");
	const parentTournament = document.querySelector(".match-history-tournament");
	parentVersus.textContent = ""
	parentTournament.textContent = ""
	if (JSONdata.matches.length) {
		const header = document.createElement('h5')
		header.textContent = "VERSUS";
		parentVersus.appendChild(header)
		JSONdata.matches.forEach(versusMatch=>{
			const versusItem = document.createElement('div');
			versusItem.classList.add("match-history-versus-item")
			const versusTime = document.createElement('h5');
			versusTime.classList.add("match-history-versus-time");
			const dateObject = new Date(versusMatch.created_on);
			const day = dateObject.getDate();
			const month = dateObject.toLocaleString('default', { month: 'short' });
			const year = dateObject.getFullYear()
			const hour = dateObject.getHours().toString().padStart(2, '0');
			const minute = dateObject.getMinutes().toString().padStart(2, '0')
			versusTime.textContent = `${day} ${month} ${year} ${hour}:${minute}`;
			const versusTeamOne = document.createElement('div');
			versusTeamOne.classList.add("match-history-versus-teamone")
			const versusTeamTwo = document.createElement('div');
			versusTeamTwo.classList.add("match-history-versus-teamtwo")
			const versusTeamOneScore = document.createElement('p');
			versusTeamOneScore.classList.add("match-history-versus-teamone-score");
			const versusTeamTwoScore = document.createElement('p');
			versusTeamTwoScore.classList.add("match-history-versus-teamtwo-score");
			versusMatch.t1.forEach(t1=>{
				const playerButton = document.createElement('button');
				const span = document.createElement('span');
				const img = document.createElement('img');
				playerButton.setAttribute("type", "button");
				playerButton.classList.add("match-history-versus-button");
				playerButton.classList.add(t1);
				if (username_list.every(username=>{
					return username !== t1;
				})) {
					fetch_match_history_profile_pic(t1)
					username_list.push(t1);
				}
				img.setAttribute("src", "/");
				span.textContent=t1;
				playerButton.appendChild(img);
				playerButton.appendChild(span);
				versusTeamOne.appendChild(playerButton);
			})
			versusMatch.t2.forEach(t2=>{
				const playerButton = document.createElement('button');
				const span = document.createElement('span');
				const img = document.createElement('img');
				playerButton.setAttribute("type", "button");
				playerButton.classList.add("match-history-versus-button");
				playerButton.classList.add(t2);
				if (username_list.every(username=>{
					return username !== t2;
				})) {
					fetch_match_history_profile_pic(t2)
					username_list.push(t2);
				}
				img.setAttribute("src", "/");
				span.textContent=t2;
				playerButton.appendChild(img);
				playerButton.appendChild(span);
				versusTeamTwo.appendChild(playerButton);
			})
			versusTeamOneScore.textContent = versusMatch.t1_points;
			versusTeamTwoScore.textContent = versusMatch.t2_points;
			versusItem.appendChild(versusTime);
			versusItem.appendChild(versusTeamOne);
			versusItem.appendChild(versusTeamOneScore);
			versusItem.appendChild(versusTeamTwo);
			versusItem.appendChild(versusTeamTwoScore);
			parentVersus.appendChild(versusItem);
		})
	}
	if (JSONdata.tournaments.length) {
		const header = document.createElement('h5')
		header.textContent = "TOURNAMENT";
		parentTournament.appendChild(header)
		JSONdata.tournaments.forEach(tournament=>{
			const tournamentItem = document.createElement('div');
			tournamentItem.classList.add("match-history-tournament-item")
			const winner = document.createElement('h5');
			winner.classList.add("match-history-tournament-winner");
			winner.textContent = "Winner: " + tournament.winner;
			const dateObject = new Date(tournament.created_on);
			const day = dateObject.getDate();
			const month = dateObject.toLocaleString('default', { month: 'short' });
			const year = dateObject.getFullYear()
			const hour = dateObject.getHours().toString().padStart(2, '0');
			const minute = dateObject.getMinutes().toString().padStart(2, '0')
			const tournamentTime = document.createElement('h5');
			tournamentTime.classList.add("match-history-tournament-time");
			tournamentTime.textContent = `${day} ${month} ${year} ${hour}:${minute}`;
			tournamentItem.appendChild(winner);
			tournamentItem.appendChild(tournamentTime);
			tournament.matches.forEach(matches=>{
				const tournamentButtonOne = document.createElement('button');
				const spanOne = document.createElement('span');
				const imgOne = document.createElement('img');
				tournamentButtonOne.classList.add("match-history-tournament-button");
				tournamentButtonOne.classList.add(matches.t1[0])
				if (username_list.every(username=>{
					return username !== matches.t1[0];
				})) {
					fetch_match_history_profile_pic(matches.t1[0])
					username_list.push(matches.t1[0]);
				}
				spanOne.textContent = matches.t1[0];
				imgOne.setAttribute("src", "/");
				tournamentButtonOne.appendChild(imgOne);
				tournamentButtonOne.appendChild(spanOne);
				const tournamentButtonTwo = document.createElement('button');
				const spanTwo = document.createElement('span');
				const imgTwo = document.createElement('img');
				tournamentButtonTwo.classList.add("match-history-tournament-button");
				tournamentButtonTwo.classList.add(matches.t2[0])
				if (username_list.every(username=>{
					return username !== matches.t2[0];
				})) {
					fetch_match_history_profile_pic(matches.t2[0])
					username_list.push(matches.t2[0]);
				}
				spanTwo.textContent = matches.t2[0];
				imgTwo.setAttribute("src", "/");
				tournamentButtonTwo.appendChild(imgTwo);
				tournamentButtonTwo.appendChild(spanTwo);
				const tournamentTeamOneScore = document.createElement('p');
				tournamentTeamOneScore.classList.add("match-history-tournament-teamone-score");
				tournamentTeamOneScore.textContent = matches.t1_points;
				const tournamentTeamTwoScore = document.createElement('p');
				tournamentTeamTwoScore.classList.add("match-history-tournament-teamtwo-score");
				tournamentTeamTwoScore.textContent = matches.t2_points;
				tournamentItem.appendChild(tournamentButtonOne);
				tournamentItem.appendChild(tournamentTeamOneScore);
				tournamentItem.appendChild(tournamentButtonTwo);
				tournamentItem.appendChild(tournamentTeamTwoScore);
			})
			parentTournament.appendChild(tournamentItem);
		})
	}
	
	
	
}




export { keyBindingProfile, populateProfile, fetch_profile, fetch_matchHistory };