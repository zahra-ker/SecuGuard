// popup.js - script pour l'interface utilisateur de l'extension

// éléments DOM
const statusIcon = document.getElementById('statusIcon');
const statusTitle = document.getElementById('statusTitle');
const statusMessage = document.getElementById('statusMessage');
const safetyIndicator = document.getElementById('safetyIndicator');
const safetyScore = document.getElementById('safetyScore');
const riskDetails = document.getElementById('riskDetails');
const risksList = document.getElementById('risksList');
const whitelistBtn = document.getElementById('whitelistBtn');
const reportBtn = document.getElementById('reportBtn');
const phishingDetection = document.getElementById('phishingDetection');
const malwareDetection = document.getElementById('malwareDetection');
const notificationLevel = document.getElementById('notificationLevel');
const whitelistItems = document.getElementById('whitelistItems');

// données courantes
let currentTabUrl = '';
let currentDomain = '';
let currentSecurityDetails = null;
let isInWhitelist = false;

// initialisation au chargement du popup
document.addEventListener('DOMContentLoaded', () => {
  // charge les paramètres courants
  loadSettings();
  
  // récupère le statut du site actuel
  getCurrentTabInfo();
  
  // charge la liste des sites de confiance
  loadWhitelist();
  
  // initialise les écouteurs d'événements
  initEventListeners();
});

/**
 * charge les paramètres depuis le stockage local
 */
function loadSettings() {
  chrome.storage.local.get([
    'enablePhishingDetection',
    'enableMalwareDetection',
    'notificationLevel'
  ], (settings) => {
    // paramètres de détection
    phishingDetection.checked = settings.enablePhishingDetection !== false;
    malwareDetection.checked = settings.enableMalwareDetection !== false;
    
    // niveau de notification
    if (settings.notificationLevel) {
      notificationLevel.value = settings.notificationLevel;
    }
  });
}

/**
 * récupère les informations sur l'onglet courant
 */
function getCurrentTabInfo() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length === 0) {
      // aucun onglet actif
      updateUIForNoTab();
      return;
    }
    
    const tab = tabs[0];
    currentTabUrl = tab.url;
    
    try {
      const urlObj = new URL(currentTabUrl);
      currentDomain = urlObj.hostname;
      
      // vérifie si le domaine est dans la liste blanche
      checkIfInWhitelist(currentDomain);
      
      // vérifie les informations de sécurité pour cet onglet
      getSiteSecurityStatus();
    } catch (error) {
      // URL invalide
      updateUIForInvalidTab();
    }
  });
}

/**
 * vérifie si le domaine actuel est dans la liste blanche
 * @param {string} domain - le domaine à vérifier
 */
function checkIfInWhitelist(domain) {
  chrome.storage.local.get('whitelist', (data) => {
    const whitelist = data.whitelist || [];
    isInWhitelist = whitelist.includes(domain);
    
    // met à jour l'état du bouton de liste blanche
    updateWhitelistButtonState();
  });
}

/**
 * met à jour l'état du bouton de liste blanche
 */
function updateWhitelistButtonState() {
  if (isInWhitelist) {
    whitelistBtn.textContent = 'Retirer de la liste blanche';
    whitelistBtn.classList.add('secondary');
  } else {
    whitelistBtn.textContent = 'Ajouter à la liste blanche';
    whitelistBtn.classList.remove('secondary');
  }
}

/**
 * récupère le statut de sécurité du site actuel
 */
function getSiteSecurityStatus() {
  chrome.runtime.sendMessage({ action: 'getSiteStatus' }, (response) => {
    if (response && response.success) {
      currentSecurityDetails = response.data;
      updateUIWithSecurityDetails();
    } else {
      // erreur lors de la récupération du statut
      updateUIForError();
    }
  });
}

/**
 * met à jour l'interface avec les détails de sécurité
 */
function updateUIWithSecurityDetails() {
  // si le site est dans la liste blanche, on le considère comme sûr
  if (isInWhitelist) {
    updateUIForSafeSite('Site de confiance', 'Ce site est dans votre liste blanche');
    return;
  }
  
  const score = currentSecurityDetails.safetyScore;
  
  // met à jour l'indicateur de sécurité
  safetyIndicator.style.width = `${score}%`;
  safetyScore.textContent = `${score}/100`;
  
  // détermine la classe de couleur en fonction du score
  safetyIndicator.className = 'safety-indicator';
  if (score >= 70) {
    safetyIndicator.classList.add('safe');
    statusIcon.innerHTML = '✓';
    statusIcon.parentElement.className = 'status-icon safe';
  } else if (score >= 40) {
    safetyIndicator.classList.add('warning');
    statusIcon.innerHTML = '!';
    statusIcon.parentElement.className = 'status-icon warning';
  } else {
    safetyIndicator.classList.add('danger');
    statusIcon.innerHTML = '!!';
    statusIcon.parentElement.className = 'status-icon danger';
  }
  
  // met à jour le titre et le message
  if (score >= 70) {
    statusTitle.textContent = 'Site sécurisé';
    statusMessage.textContent = 'Aucun risque majeur détecté sur ce site.';
    riskDetails.style.display = 'none';
  } else if (score >= 40) {
    statusTitle.textContent = 'Attention requise';
    statusMessage.textContent = 'Ce site présente quelques risques potentiels.';
    displayRiskDetails();
  } else {
    statusTitle.textContent = 'Site potentiellement dangereux';
    statusMessage.textContent = 'Des risques importants ont été détectés sur ce site.';
    displayRiskDetails();
  }
}

/**
 * affiche les détails des risques détectés
 */
function displayRiskDetails() {
  // vide la liste des risques
  risksList.innerHTML = '';
  
  // vérifie s'il y a des risques à afficher
  if (currentSecurityDetails && currentSecurityDetails.risks && currentSecurityDetails.risks.length > 0) {
    // affiche le panneau des risques
    riskDetails.style.display = 'block';
    
    // crée un élément de liste pour chaque risque
    currentSecurityDetails.risks.forEach(risk => {
      const listItem = document.createElement('li');
      listItem.textContent = risk.description;
      risksList.appendChild(listItem);
    });
  } else {
    // aucun risque détaillé disponible, cache le panneau
    riskDetails.style.display = 'none';
  }
}

/**
 * met à jour l'interface pour un site considéré comme sûr
 * @param {string} title - titre à afficher
 * @param {string} message - message à afficher
 */
function updateUIForSafeSite(title, message) {
  statusTitle.textContent = title;
  statusMessage.textContent = message;
  
  safetyIndicator.style.width = '100%';
  safetyIndicator.className = 'safety-indicator safe';
  safetyScore.textContent = '100/100';
  
  statusIcon.innerHTML = '✓';
  statusIcon.parentElement.className = 'status-icon safe';
  
  riskDetails.style.display = 'none';
}

/**
 * met à jour l'interface lorsqu'aucun onglet n'est actif
 */
function updateUIForNoTab() {
  statusTitle.textContent = 'Aucun site actif';
  statusMessage.textContent = 'Ouvrez un site web pour analyser sa sécurité.';
  
  safetyIndicator.style.width = '0%';
  safetyIndicator.className = 'safety-indicator';
  safetyScore.textContent = '--/100';
  
  statusIcon.innerHTML = '?';
  statusIcon.parentElement.className = 'status-icon';
  
  riskDetails.style.display = 'none';
}

/**
 * met à jour l'interface pour un onglet invalide
 */
function updateUIForInvalidTab() {
  statusTitle.textContent = 'Page non analysable';
  statusMessage.textContent = 'Impossible d\'analyser cette page (chrome://, file://, etc.)';
  
  safetyIndicator.style.width = '0%';
  safetyIndicator.className = 'safety-indicator';
  safetyScore.textContent = '--/100';
  
  statusIcon.innerHTML = '?';
  statusIcon.parentElement.className = 'status-icon';
  
  riskDetails.style.display = 'none';
}

/**
 * met à jour l'interface en cas d'erreur
 */
function updateUIForError() {
  statusTitle.textContent = 'Erreur d\'analyse';
  statusMessage.textContent = 'Impossible d\'obtenir les informations de sécurité.';
  
  safetyIndicator.style.width = '0%';
  safetyIndicator.className = 'safety-indicator';
  safetyScore.textContent = '--/100';
  
  statusIcon.innerHTML = '!';
  statusIcon.parentElement.className = 'status-icon warning';
  
  riskDetails.style.display = 'none';
}

/**
 * charge la liste des sites de confiance
 */
function loadWhitelist() {
  chrome.storage.local.get('whitelist', (data) => {
    const whitelist = data.whitelist || [];
    
    // vide la liste
    whitelistItems.innerHTML = '';
    
    if (whitelist.length === 0) {
      // affiche un message si la liste est vide
      const emptyItem = document.createElement('li');
      emptyItem.textContent = 'Aucun site dans la liste blanche';
      emptyItem.style.color = '#95a5a6';
      whitelistItems.appendChild(emptyItem);
    } else {
      // peuple la liste avec les domaines en liste blanche
      whitelist.forEach(domain => {
        const listItem = document.createElement('li');
        
        const domainSpan = document.createElement('span');
        domainSpan.textContent = domain;
        listItem.appendChild(domainSpan);
        
        const removeButton = document.createElement('button');
        removeButton.textContent = '×';
        removeButton.className = 'remove-whitelist';
        removeButton.title = 'Retirer de la liste blanche';
        removeButton.dataset.domain = domain;
        removeButton.addEventListener('click', handleRemoveFromWhitelist);
        listItem.appendChild(removeButton);
        
        whitelistItems.appendChild(listItem);
      });
    }
  });
}

/**
 * initialise les écouteurs d'événements
 */
function initEventListeners() {
  // bouton d'ajout/retrait de la liste blanche
  whitelistBtn.addEventListener('click', handleWhitelistButtonClick);
  
  // bouton de signalement
  reportBtn.addEventListener('click', handleReportButtonClick);
  
  // écouteurs pour les changements de paramètres
  phishingDetection.addEventListener('change', handleSettingChange);
  malwareDetection.addEventListener('change', handleSettingChange);
  notificationLevel.addEventListener('change', handleSettingChange);
}

/**
 * gère le clic sur le bouton de liste blanche
 */
function handleWhitelistButtonClick() {
  if (isInWhitelist) {
    // retire le domaine de la liste blanche
    chrome.runtime.sendMessage({
      action: 'removeFromWhitelist',
      domain: currentDomain
    }, (response) => {
      if (response && response.success) {
        isInWhitelist = false;
        updateWhitelistButtonState();
        loadWhitelist();
        getSiteSecurityStatus();
      }
    });
  } else {
    // ajoute le domaine à la liste blanche
    chrome.runtime.sendMessage({
      action: 'addToWhitelist',
      domain: currentDomain
    }, (response) => {
      if (response && response.success) {
        isInWhitelist = true;
        updateWhitelistButtonState();
        loadWhitelist();
        updateUIForSafeSite('Site de confiance', 'Ce site a été ajouté à votre liste blanche');
      }
    });
  }
}

/**
 * gère le clic sur le bouton de signalement, à implémenter
 */
/* function handleReportButtonClick() {
  // ouvre une page de feedback ou un formulaire de rapport

} */

/**
 * gère les changements de paramètres
 * @param {Event} event - l'événement de changement
 */
function handleSettingChange(event) {
  // détermine le type de paramètre modifié
  const setting = event.target;
  
  if (setting.id === 'phishingDetection') {
    // paramètre de détection de phishing
    chrome.storage.local.set({ enablePhishingDetection: setting.checked });
  } else if (setting.id === 'malwareDetection') {
    // paramètre de détection de malware
    chrome.storage.local.set({ enableMalwareDetection: setting.checked });
  } else if (setting.id === 'notificationLevel') {
    // niveau de notification
    chrome.storage.local.set({ notificationLevel: setting.value });
  }
}

/**
 * gère le clic sur le bouton de retrait de la liste blanche
 * @param {Event} event - l'événement de clic
 */
function handleRemoveFromWhitelist(event) {
  const domain = event.target.dataset.domain;
  
  chrome.runtime.sendMessage({
    action: 'removeFromWhitelist',
    domain: domain
  }, (response) => {
    if (response && response.success) {
      // recharge la liste blanche
      loadWhitelist();
      
      // si le domaine actuel a été retiré, met à jour l'état
      if (domain === currentDomain) {
        isInWhitelist = false;
        updateWhitelistButtonState();
        getSiteSecurityStatus();
      }
    }
  });
}