// content.js - script injecté dans les pages web visitées

// variables globales
let securityDetails = null;
let notificationContainer = null;

// initialise l'analyse de la page au chargement
initializePageScan();

/**
 * initialise l'analyse de sécurité de la page
 */
function initializePageScan() {
  // analyse le contenu de la page pour des éléments suspects
  analyzePageContent();
  
  // écoute les formulaires pour détecter des activités de phishing potentielles
  detectPhishingForms();
  
  // crée le conteneur pour les notifications (caché par défaut)
  createNotificationContainer();
  
  // écoute les messages du script d'arrière-plan
  listenForBackgroundMessages();
}

/**
 * analyse le contenu de la page pour détecter des éléments suspects
 */
function analyzePageContent() {
  // recherche des indicateurs de phishing courants dans le contenu de la page
  const pageText = document.body.innerText.toLowerCase();
  const pageTitle = document.title.toLowerCase();
  const phishingIndicators = [
    'verify your account',
    'confirm your identity',
    'suspicious activity',
    'update your payment',
    'your account has been limited',
    'login to continue',
    'secure login',
    'please re-enter your password'
  ];
  
  const results = {
    suspiciousContent: false,
    reasons: []
  };
  
  // vérifie la présence d'indicateurs de phishing
  phishingIndicators.forEach(indicator => {
    if (pageText.includes(indicator.toLowerCase())) {
      results.suspiciousContent = true;
      results.reasons.push(`texte suspect détecté: "${indicator}"`);
    }
  });
  
  // vérifie si le titre contient des termes associés à la sécurité/connexion
  const titleIndicators = ['secure', 'login', 'sign in', 'verify', 'confirm', 'update'];
  titleIndicators.forEach(indicator => {
    if (pageTitle.includes(indicator)) {
      results.suspiciousContent = true;
      results.reasons.push(`titre suspect: contient "${indicator}"`);
    }
  });
  
  // vérifie les redirections via meta refresh
  const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
  if (metaRefresh) {
    results.suspiciousContent = true;
    results.reasons.push('redirection automatique via meta refresh détectée');
  }
  
  // vérifie les iframes cachés qui pourraient être utilisés pour le clickjacking
  const hiddenIframes = Array.from(document.querySelectorAll('iframe')).filter(iframe => {
    const style = window.getComputedStyle(iframe);
    return style.display === 'none' || style.visibility === 'hidden' || 
           parseInt(style.opacity) === 0 || 
           (parseInt(style.width) <= 1 && parseInt(style.height) <= 1);
  });
  
  if (hiddenIframes.length > 0) {
    results.suspiciousContent = true;
    results.reasons.push(`${hiddenIframes.length} iframe(s) caché(s) détecté(s), possible tentative de clickjacking`);
  }
  
  // envoie les résultats au script d'arrière-plan
  if (results.suspiciousContent) {
    chrome.runtime.sendMessage({
      action: 'contentAnalysisResults',
      data: results
    });
  }
}

/**
 * détecte les formulaires qui pourraient être utilisés pour le phishing
 */
function detectPhishingForms() {
  // sélectionne tous les formulaires de la page
  const forms = document.querySelectorAll('form');
  
  forms.forEach(form => {
    // vérifie les formulaires avec des champs de mot de passe
    const passwordFields = form.querySelectorAll('input[type="password"]');
    const loginFields = form.querySelectorAll('input[type="text"], input[type="email"]');
    
    if (passwordFields.length > 0) {
      // surveille les soumissions de formulaire de connexion
      form.addEventListener('submit', (event) => {
        // vérifie si le site est considéré comme sûr
        if (securityDetails && securityDetails.safetyScore < 70) {
          // si le site n'est pas sûr, demande confirmation avant d'envoyer les données
          if (!confirm('Attention: Vous êtes sur le point d\'envoyer vos identifiants à un site potentiellement dangereux. Continuer quand même?')) {
            event.preventDefault();
            event.stopPropagation();
          }
        }
      });
      
      // ajoute un avertissement visuel aux formulaires de connexion sur les sites suspects
      if (securityDetails && securityDetails.safetyScore < 50) {
        const warningElement = document.createElement('div');
        warningElement.style.color = '#721c24';
        warningElement.style.backgroundColor = '#f8d7da';
        warningElement.style.padding = '10px';
        warningElement.style.borderRadius = '4px';
        warningElement.style.marginBottom = '10px';
        warningElement.style.border = '1px solid #f5c6cb';
        warningElement.textContent = 'Attention: Ce formulaire pourrait être utilisé pour voler vos identifiants. Vérifiez l\'URL avant de soumettre vos informations.';
        
        // insère l'avertissement avant le formulaire
        form.parentNode.insertBefore(warningElement, form);
      }
    }
  });
}

/**
 * crée le conteneur pour les notifications d'alerte
 */
function createNotificationContainer() {
  notificationContainer = document.createElement('div');
  notificationContainer.style.position = 'fixed';
  notificationContainer.style.top = '10px';
  notificationContainer.style.right = '10px';
  notificationContainer.style.zIndex = '9999';
  notificationContainer.style.maxWidth = '400px';
  notificationContainer.style.display = 'none';
  
  document.body.appendChild(notificationContainer);
}

/**
 * affiche une notification d'alerte
 * @param {string} title - titre de la notification
 * @param {string} message - message principal
 * @param {object} details - détails supplémentaires
 */
function showNotification(title, message, details) {
  // crée l'élément de notification
  const notificationElement = document.createElement('div');
  notificationElement.style.backgroundColor = '#f8d7da';
  notificationElement.style.color = '#721c24';
  notificationElement.style.padding = '15px';
  notificationElement.style.marginBottom = '10px';
  notificationElement.style.borderRadius = '6px';
  notificationElement.style.boxShadow = '0 4px 8px rgba(0, 0, 0, 0.1)';
  notificationElement.style.border = '1px solid #f5c6cb';
  notificationElement.style.position = 'relative';
  
  // titre de la notification
  const titleElement = document.createElement('h3');
  titleElement.style.margin = '0 0 8px 0';
  titleElement.style.fontSize = '16px';
  titleElement.textContent = title;
  
  // message principal
  const messageElement = document.createElement('p');
  messageElement.style.margin = '0 0 10px 0';
  messageElement.style.fontSize = '14px';
  messageElement.textContent = message;
  
  // détails (risques spécifiques)
  const detailsList = document.createElement('ul');
  detailsList.style.margin = '0';
  detailsList.style.paddingLeft = '20px';
  detailsList.style.fontSize = '12px';
  
  if (details && details.risks) {
    details.risks.forEach(risk => {
      const riskItem = document.createElement('li');
      riskItem.textContent = risk.description;
      detailsList.appendChild(riskItem);
    });
  }
  
  // bouton de fermeture
  const closeButton = document.createElement('button');
  closeButton.textContent = '×';
  closeButton.style.position = 'absolute';
  closeButton.style.top = '5px';
  closeButton.style.right = '5px';
  closeButton.style.border = 'none';
  closeButton.style.background = 'none';
  closeButton.style.fontSize = '20px';
  closeButton.style.cursor = 'pointer';
  closeButton.style.color = '#721c24';
  closeButton.onclick = () => {
    notificationElement.remove();
    
    // cache le conteneur s'il n'y a plus de notifications
    if (notificationContainer.children.length === 0) {
      notificationContainer.style.display = 'none';
    }
  };
  
  // assemble la notification
  notificationElement.appendChild(closeButton);
  notificationElement.appendChild(titleElement);
  notificationElement.appendChild(messageElement);
  
  if (details && details.risks && details.risks.length > 0) {
    notificationElement.appendChild(detailsList);
  }
  
  // ajoute un bouton pour ajouter le site à la liste blanche
  const whitelistButton = document.createElement('button');
  whitelistButton.textContent = 'Faire confiance à ce site';
  whitelistButton.style.marginTop = '10px';
  whitelistButton.style.padding = '5px 10px';
  whitelistButton.style.backgroundColor = '#f8f9fa';
  whitelistButton.style.border = '1px solid #ddd';
  whitelistButton.style.borderRadius = '4px';
  whitelistButton.style.cursor = 'pointer';
  whitelistButton.onclick = () => {
    // demande au script d'arrière-plan d'ajouter le domaine à la liste blanche
    chrome.runtime.sendMessage({
      action: 'addToWhitelist',
      domain: details.domain
    }, () => {
      notificationElement.remove();
      // actualise la page pour refléter le changement
      window.location.reload();
    });
  };
  
  notificationElement.appendChild(whitelistButton);
  
  // affiche le conteneur et ajoute la notification
  notificationContainer.style.display = 'block';
  notificationContainer.appendChild(notificationElement);
}

/**
 * écoute les messages du script d'arrière-plan
 */
function listenForBackgroundMessages() {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'securityResult') {
      // stocke les détails de sécurité
      securityDetails = request.data;
    }
    
    if (request.action === 'showNotification') {
      // affiche une notification avec les détails fournis
      const { title, message, details } = request.data;
      showNotification(title, message, details);
    }
  });
}