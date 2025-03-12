// background.js - script principal qui s'exécute en arrière-plan

// liste de domaines malveillants connus (à remplacer par une API réelle)
// qui répertorie une liste d'urls malveillantes
const maliciousDomains = [
  'evil-phishing.com',
  'fake-bank-login.net',
  'free-prizes-scam.org',
  'login-paypal-secure-verification.com',

  // sites safes uniquement présents pour tester la détection de sites malveillants
  // 'example.com',
  // 'stackoverflow.com', 
  // 'github.com'
];

// dictionnaire de mots-clés souvent utilisés dans les attaques de phishing
const phishingKeywords = [
  'verify your account',
  'update your payment information',
  'unusual activity detected',
  'login to prevent account suspension',
  'confirm your identity'
];

// scores de risque
const RISK = {
  SAFE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};

// initialisation de l'extension
chrome.runtime.onInstalled.addListener(() => {
  // initialisation des paramètres par défaut dans le stockage local
  chrome.storage.local.set({
    enablePhishingDetection: true,
    enableMalwareDetection: true,
    notificationLevel: 'all', // 'all', 'medium+', 'high+'
    whitelist: []
  });
  
  console.log('extension SecuGuard installée et initialisée');
});

// écouteur pour les changements d'onglet
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // ne vérifie que lorsque la page est complètement chargée
  if (changeInfo.status === 'complete' && tab.url) {
    // récupère les paramètres actuels
    chrome.storage.local.get([
      'enablePhishingDetection',
      'enableMalwareDetection',
      'whitelist'
    ], (settings) => {
      // vérifie si l'URL est dans la liste blanche
      const urlObj = new URL(tab.url);
      const domain = urlObj.hostname;
      
      if (settings.whitelist.includes(domain)) {
        // domaine en liste blanche, pas d'analyse nécessaire
        updateBadge(tabId, RISK.SAFE);
        return;
      }
      
      // analyse le site pour les risques potentiels
      analyzeSite(tab.url, tabId);
    });
  }
});

/**
 * analyse une URL pour détecter des menaces potentielles
 * @param {string} url - l'URL à analyser
 * @param {number} tabId - l'identifiant de l'onglet actuel
 */
async function analyzeSite(url, tabId) {
  let riskScore = RISK.SAFE;
  const urlObj = new URL(url);
  const domain = urlObj.hostname;
  let securityDetails = {
    domain: domain,
    risks: [],
    safetyScore: 100,
    timestamp: Date.now()
  };

  // mode test - force une détection pour faciliter les tests
  const forceTestMode = false;
  if (forceTestMode) {
    console.log("Extension en mode test - simulation d'un site suspect");
    riskScore = RISK.HIGH;
    securityDetails.risks.push({
      type: 'testMode',
      severity: 'high',
      description: 'Mode de test activé - simulation d\'un site à risque'
    });
    securityDetails.safetyScore = 30;

    updateBadge(tabId, riskScore);
    notifyUser(tabId, securityDetails);
    saveSecurityDetails(url, securityDetails);

    // Débogage
    console.log('URL analysée:', url);
    console.log('Score de risque:', riskScore);
    console.log('Détails de sécurité:', securityDetails);
    return;
  }
  
  // vérifie si le domaine est dans notre liste de domaines malveillants
  if (maliciousDomains.includes(domain)) {
    riskScore = RISK.CRITICAL;
    securityDetails.risks.push({
      type: 'knownMalicious',
      severity: 'critical',
      description: 'domaine identifié comme malveillant dans notre base de données'
    });
    securityDetails.safetyScore = 0;
  }
  
  // vérifie si c'est un site sécurisé (HTTPS)
  if (urlObj.protocol !== 'https:') {
    riskScore = Math.max(riskScore, RISK.MEDIUM);
    securityDetails.risks.push({
      type: 'insecureConnection',
      severity: 'medium',
      description: 'connexion non sécurisée (HTTP au lieu de HTTPS)'
    });
    securityDetails.safetyScore -= 30;
  }
  
  // vérifie si le domaine ressemble à une usurpation d'identité d'une marque connue
  const brandPhishingScore = checkForBrandSpoofing(domain);
  if (brandPhishingScore > 0) {
    riskScore = Math.max(riskScore, brandPhishingScore);
    securityDetails.risks.push({
      type: 'possibleSpoofing',
      severity: brandPhishingScore === RISK.HIGH ? 'high' : 'medium',
      description: 'ce domaine pourrait usurper l\'identité d\'une marque légitime'
    });
    securityDetails.safetyScore -= (brandPhishingScore * 15);
  }
  
  // vérifie certains paramètres d'URL suspects
  if (urlObj.search.includes('password') || urlObj.search.includes('login') || urlObj.search.includes('account')) {
    riskScore = Math.max(riskScore, RISK.LOW);
    securityDetails.risks.push({
      type: 'sensitiveParams',
      severity: 'low',
      description: 'des informations sensibles pourraient être transmises dans l\'URL'
    });
    securityDetails.safetyScore -= 10;
  }
  
  // vérifie pour les redirections suspectes
  if (urlObj.search.includes('redirect') || urlObj.search.includes('return_to') || urlObj.search.includes('goto')) {
    riskScore = Math.max(riskScore, RISK.LOW);
    securityDetails.risks.push({
      type: 'possibleRedirection',
      severity: 'low',
      description: 'cette page pourrait rediriger vers un site malveillant'
    });
    securityDetails.safetyScore -= 15;
  }
  
  // normalise le score de sécurité entre 0 et 100
  securityDetails.safetyScore = Math.max(0, Math.min(100, securityDetails.safetyScore));
  
  // sauvegarde les détails pour cet URL dans le stockage local
  saveSecurityDetails(url, securityDetails);
  
  // met à jour le badge de l'extension
  updateBadge(tabId, riskScore);
  
  // si le risque est élevé ou critique, envoie une notification
  if (riskScore >= RISK.HIGH) {
    notifyUser(tabId, securityDetails);
  }
  
  // envoie les résultats à l'onglet actuel pour que le content script puisse réagir
  chrome.tabs.sendMessage(tabId, {
    action: 'securityResult',
    data: securityDetails
  }).catch(error => {
    // gestion silencieuse des erreurs si le message ne peut pas être envoyé
    console.error('erreur lors de l\'envoi des résultats de sécurité au content script:', error);
  });
}

/**
 * vérifie si un domaine essaie d'usurper l'identité d'une marque connue
 * @param {string} domain - le domaine à vérifier
 * @return {number} - le niveau de risque détecté
 */
function checkForBrandSpoofing(domain) {
  // liste des marques populaires souvent ciblées par les attaques de phishing
  const popularBrands = [
    'paypal',
    'apple',
    'amazon',
    'microsoft',
    'netflix',
    'google',
    'facebook',
    'instagram',
    'twitter',
    'linkedin',
    'banque'
  ];
  
  // recherche de similitudes avec des marques connues
  for (const brand of popularBrands) {
    if (domain.includes(brand) && !domain.startsWith(brand + '.')) {
      // si le domaine contient une marque mais n'est pas le domaine officiel
      if (domain.includes('-' + brand) || domain.includes(brand + '-') || 
          domain.includes('.' + brand + '.') || 
          domain.includes(brand + 'secure') || 
          domain.includes('secure' + brand)) {
        return RISK.HIGH;  // forte probabilité d'usurpation
      }
      
      // similarité simple
      return RISK.MEDIUM;  // possible usurpation
    }
  }
  
  return RISK.SAFE;  // pas d'usurpation détectée
}

/**
 * met à jour le badge de l'extension pour indiquer le niveau de risque
 * @param {number} tabId - l'identifiant de l'onglet
 * @param {number} riskLevel - le niveau de risque détecté
 */
function updateBadge(tabId, riskLevel) {
  let badgeText = '';
  let badgeColor = '#4CAF50';  // vert par défaut (sécurisé)
  
  switch (riskLevel) {
    case RISK.SAFE:
      badgeText = '';
      break;
    case RISK.LOW:
      badgeText = '!';
      badgeColor = '#2196F3';  // bleu
      break;
    case RISK.MEDIUM:
      badgeText = '!!';
      badgeColor = '#FF9800';  // orange
      break;
    case RISK.HIGH:
      badgeText = '!!!';
      badgeColor = '#F44336';  // rouge
      break;
    case RISK.CRITICAL:
      badgeText = '!!!';
      badgeColor = '#B71C1C';  // rouge foncé
      break;
  }
  
  chrome.action.setBadgeText({ text: badgeText, tabId: tabId });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId });
}

/**
 * enregistre les détails de sécurité pour une URL
 * @param {string} url - l'URL analysée
 * @param {object} details - les détails de sécurité
 */
function saveSecurityDetails(url, details) {
  chrome.storage.local.get('securityHistory', (data) => {
    const history = data.securityHistory || {};
    
    // limite l'historique à 100 entrées
    const urlKeys = Object.keys(history);
    if (urlKeys.length >= 100) {
      // supprime l'entrée la plus ancienne
      delete history[urlKeys[0]];
    }
    
    // ajoute la nouvelle entrée
    history[url] = details;
    
    // sauvegarde l'historique mis à jour
    chrome.storage.local.set({ securityHistory: history });
  });
}

/**
 * notifie l'utilisateur d'un risque élevé
 * @param {number} tabId - l'identifiant de l'onglet
 * @param {object} details - les détails de sécurité
 */
function notifyUser(tabId, details) {
  // obtient les paramètres de notification
  chrome.storage.local.get('notificationLevel', (settings) => {
    const level = settings.notificationLevel || 'all';
    
    // vérifie si on doit montrer la notification en fonction du niveau configuré
    const riskLevel = getRiskLevelFromDetails(details);
    if ((level === 'medium+' && riskLevel < RISK.MEDIUM) ||
        (level === 'high+' && riskLevel < RISK.HIGH)) {
      return;  // ne pas montrer la notification
    }
    
    // crée une notification dans l'interface
    chrome.tabs.sendMessage(tabId, {
      action: 'showNotification',
      data: {
        title: 'Alerte de sécurité',
        message: `Risque détecté sur ${details.domain}`,
        details: details
      }
    }).catch(error => {
      // en cas d'échec, affiche une alerte système
      console.error('échec de l\'envoi de notification:', error);
    });
  });
}

/**
 * détermine le niveau de risque global à partir des détails
 * @param {object} details - les détails de sécurité
 * @return {number} - le niveau de risque
 */
function getRiskLevelFromDetails(details) {
  if (details.safetyScore < 20) return RISK.CRITICAL;
  if (details.safetyScore < 40) return RISK.HIGH;
  if (details.safetyScore < 60) return RISK.MEDIUM;
  if (details.safetyScore < 80) return RISK.LOW;
  return RISK.SAFE;
}

// écouteur pour les messages provenant du popup ou du content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getSiteStatus') {
    // récupère le statut de sécurité du site actuel
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length === 0) {
        sendResponse({ success: false, error: 'aucun onglet actif' });
        return;
      }
      
      const currentUrl = tabs[0].url;
      
      // récupère l'historique de sécurité
      chrome.storage.local.get('securityHistory', (data) => {
        const history = data.securityHistory || {};
        const details = history[currentUrl] || {
          domain: new URL(currentUrl).hostname,
          risks: [],
          safetyScore: 100,
          timestamp: Date.now()
        };
        
        sendResponse({ success: true, data: details });
      });
    });
    
    // indique que la réponse sera envoyée de manière asynchrone
    return true;
  }
  
  if (request.action === 'addToWhitelist') {
    // ajoute le domaine à la liste blanche
    chrome.storage.local.get('whitelist', (data) => {
      const whitelist = data.whitelist || [];
      const domain = request.domain;
      
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        chrome.storage.local.set({ whitelist: whitelist }, () => {
          sendResponse({ success: true });
        });
      } else {
        sendResponse({ success: true, message: 'domaine déjà en liste blanche' });
      }
    });
    
    // indique que la réponse sera envoyée de manière asynchrone
    return true;
  }
  
  if (request.action === 'removeFromWhitelist') {
    // supprime le domaine de la liste blanche
    chrome.storage.local.get('whitelist', (data) => {
      let whitelist = data.whitelist || [];
      const domain = request.domain;
      
      whitelist = whitelist.filter(d => d !== domain);
      chrome.storage.local.set({ whitelist: whitelist }, () => {
        sendResponse({ success: true });
      });
    });
    
    // indique que la réponse sera envoyée de manière asynchrone
    return true;
  }
});