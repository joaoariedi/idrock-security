/**
 * IDROCK JavaScript SDK for Frontend Data Collection
 * 
 * This SDK is designed for NexShop frontend integration to collect 
 * device fingerprinting data and session information for risk assessment.
 * 
 * Data flows from Frontend SDK -> NexShop Backend -> IDROCK Node.js SDK -> IDROCK API
 */

(function(window) {
  'use strict';

  /**
   * Device fingerprint collector utility
   */
  class FingerprintCollector {
    constructor() {
      this.fingerprint = null;
      this.fingerprintPromise = null;
    }

    /**
     * Collect comprehensive device fingerprint
     * 
     * @returns {Promise<string>} Device fingerprint hash
     */
    async collect() {
      if (this.fingerprintPromise) {
        return this.fingerprintPromise;
      }

      this.fingerprintPromise = this._generateFingerprint();
      return this.fingerprintPromise;
    }

    /**
     * Generate device fingerprint from multiple sources
     * 
     * @private
     * @returns {Promise<string>} Generated fingerprint
     */
    async _generateFingerprint() {
      try {
        const components = await Promise.allSettled([
          this._getCanvasFingerprint(),
          this._getWebGLFingerprint(),
          this._getAudioFingerprint(),
          this._getBrowserFeatures(),
          this._getScreenFingerprint(),
          this._getTimezoneFingerprint()
        ]);

        // Combine all successful components
        const validComponents = components
          .filter(result => result.status === 'fulfilled')
          .map(result => result.value)
          .join('|');

        // Generate hash of combined components
        const fingerprint = this._hashString(validComponents);
        
        this.fingerprint = fingerprint;
        return fingerprint;
      } catch (error) {
        console.warn('[IDROCK SDK] Fingerprint generation failed:', error);
        return this._getFallbackFingerprint();
      }
    }

    /**
     * Canvas fingerprinting
     * 
     * @private
     * @returns {string} Canvas fingerprint
     */
    _getCanvasFingerprint() {
      return new Promise((resolve) => {
        try {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          
          canvas.width = 200;
          canvas.height = 50;
          
          // Draw text with various styles
          ctx.textBaseline = 'top';
          ctx.font = '14px Arial';
          ctx.fillStyle = '#f60';
          ctx.fillRect(125, 1, 62, 20);
          ctx.fillStyle = '#069';
          ctx.fillText('IDROCK fingerprint canvas 🔒', 2, 15);
          ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
          ctx.fillText('IDROCK fingerprint canvas 🔒', 4, 17);

          // Add some geometric shapes
          ctx.globalCompositeOperation = 'multiply';
          ctx.fillStyle = 'rgb(255,0,255)';
          ctx.beginPath();
          ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
          ctx.closePath();
          ctx.fill();
          ctx.fillStyle = 'rgb(0,255,255)';
          ctx.beginPath();
          ctx.arc(100, 50, 50, 0, Math.PI * 2, true);
          ctx.closePath();
          ctx.fill();

          resolve(canvas.toDataURL());
        } catch (e) {
          resolve('canvas_error');
        }
      });
    }

    /**
     * WebGL fingerprinting
     * 
     * @private
     * @returns {string} WebGL fingerprint
     */
    _getWebGLFingerprint() {
      return new Promise((resolve) => {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          
          if (!gl) {
            resolve('no_webgl');
            return;
          }

          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '';
          const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : '';
          
          const webglInfo = [
            renderer,
            vendor,
            gl.getParameter(gl.VERSION),
            gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
          ].join('|');

          resolve(webglInfo);
        } catch (e) {
          resolve('webgl_error');
        }
      });
    }

    /**
     * Audio context fingerprinting
     * 
     * @private
     * @returns {Promise<string>} Audio fingerprint
     */
    _getAudioFingerprint() {
      return new Promise((resolve) => {
        try {
          const AudioContext = window.AudioContext || window.webkitAudioContext;
          
          if (!AudioContext) {
            resolve('no_audio_context');
            return;
          }

          const context = new AudioContext();
          const oscillator = context.createOscillator();
          const analyser = context.createAnalyser();
          const gain = context.createGain();
          const scriptProcessor = context.createScriptProcessor(4096, 1, 1);

          oscillator.type = 'triangle';
          oscillator.frequency.setValueAtTime(10000, context.currentTime);

          gain.gain.setValueAtTime(0, context.currentTime);

          oscillator.connect(analyser);
          analyser.connect(scriptProcessor);
          scriptProcessor.connect(gain);
          gain.connect(context.destination);

          scriptProcessor.onaudioprocess = function(event) {
            const output = event.outputBuffer.getChannelData(0);
            const fingerprint = Array.from(output.slice(0, 50)).join(',');
            
            oscillator.disconnect();
            scriptProcessor.disconnect();
            analyser.disconnect();
            gain.disconnect();
            context.close();

            resolve(fingerprint);
          };

          oscillator.start(0);
          
          // Timeout fallback
          setTimeout(() => {
            resolve('audio_timeout');
          }, 1000);
        } catch (e) {
          resolve('audio_error');
        }
      });
    }

    /**
     * Browser features detection
     * 
     * @private
     * @returns {string} Browser features fingerprint
     */
    _getBrowserFeatures() {
      return new Promise((resolve) => {
        try {
          const features = [
            navigator.userAgent,
            navigator.language,
            navigator.languages ? navigator.languages.join(',') : '',
            navigator.platform,
            navigator.deviceMemory || 'unknown',
            navigator.hardwareConcurrency || 'unknown',
            navigator.maxTouchPoints || 0,
            typeof navigator.doNotTrack,
            navigator.cookieEnabled
          ];

          resolve(features.join('|'));
        } catch (e) {
          resolve('browser_features_error');
        }
      });
    }

    /**
     * Screen fingerprinting
     * 
     * @private
     * @returns {string} Screen fingerprint
     */
    _getScreenFingerprint() {
      return new Promise((resolve) => {
        try {
          const screen = window.screen;
          const screenData = [
            screen.width,
            screen.height,
            screen.availWidth,
            screen.availHeight,
            screen.colorDepth,
            screen.pixelDepth,
            window.devicePixelRatio || 1,
            window.innerWidth,
            window.innerHeight,
            window.outerWidth,
            window.outerHeight
          ];

          resolve(screenData.join('|'));
        } catch (e) {
          resolve('screen_error');
        }
      });
    }

    /**
     * Timezone fingerprinting
     * 
     * @private
     * @returns {string} Timezone fingerprint
     */
    _getTimezoneFingerprint() {
      return new Promise((resolve) => {
        try {
          const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
          const offset = new Date().getTimezoneOffset();
          resolve(`${timezone}|${offset}`);
        } catch (e) {
          resolve('timezone_error');
        }
      });
    }

    /**
     * Simple hash function for fingerprint data
     * 
     * @private
     * @param {string} str - String to hash
     * @returns {string} Hash value
     */
    _hashString(str) {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
      }
      return Math.abs(hash).toString(36);
    }

    /**
     * Fallback fingerprint when collection fails
     * 
     * @private
     * @returns {string} Fallback fingerprint
     */
    _getFallbackFingerprint() {
      const fallbackData = [
        navigator.userAgent || 'unknown',
        screen.width || 0,
        screen.height || 0,
        Date.now(),
        Math.random().toString(36)
      ];
      
      return this._hashString(fallbackData.join('|'));
    }
  }

  /**
   * Session data collector
   */
  class SessionDataCollector {
    /**
     * Collect session and behavioral data
     * 
     * @returns {Object} Session data
     */
    collect() {
      return {
        timestamp: new Date().toISOString(),
        page_info: this._getPageInfo(),
        browser_info: this._getBrowserInfo(),
        performance_info: this._getPerformanceInfo(),
        interaction_data: this._getInteractionData()
      };
    }

    /**
     * Get page information
     * 
     * @private
     * @returns {Object} Page information
     */
    _getPageInfo() {
      return {
        url: window.location.href,
        referrer: document.referrer,
        title: document.title,
        domain: window.location.hostname,
        path: window.location.pathname,
        search: window.location.search,
        hash: window.location.hash
      };
    }

    /**
     * Get browser information
     * 
     * @private
     * @returns {Object} Browser information
     */
    _getBrowserInfo() {
      return {
        user_agent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages || [],
        platform: navigator.platform,
        cookie_enabled: navigator.cookieEnabled,
        do_not_track: navigator.doNotTrack,
        online: navigator.onLine,
        device_memory: navigator.deviceMemory,
        hardware_concurrency: navigator.hardwareConcurrency,
        max_touch_points: navigator.maxTouchPoints
      };
    }

    /**
     * Get performance information
     * 
     * @private
     * @returns {Object} Performance data
     */
    _getPerformanceInfo() {
      if (!window.performance || !window.performance.timing) {
        return { available: false };
      }

      const timing = window.performance.timing;
      const navigation = window.performance.navigation;

      return {
        available: true,
        load_time: timing.loadEventEnd - timing.navigationStart,
        dom_ready_time: timing.domContentLoadedEventEnd - timing.navigationStart,
        navigation_type: navigation.type,
        redirect_count: navigation.redirectCount
      };
    }

    /**
     * Get basic interaction data
     * 
     * @private
     * @returns {Object} Interaction data
     */
    _getInteractionData() {
      return {
        session_start: Date.now(),
        has_touched: 'ontouchstart' in window,
        has_mouse: matchMedia('(pointer: fine)').matches,
        viewport_width: window.innerWidth,
        viewport_height: window.innerHeight
      };
    }
  }

  /**
   * Main IDROCK JavaScript SDK class
   */
  class IDRockSDK {
    constructor(config = {}) {
      this.config = {
        // NexShop backend endpoint (NOT direct IDROCK API)
        apiEndpoint: config.apiEndpoint || '/api/security',
        timeout: config.timeout || 5000,
        retryAttempts: config.retryAttempts || 3,
        debug: config.debug || false,
        enableFingerprinting: config.enableFingerprinting !== false,
        enableSessionTracking: config.enableSessionTracking !== false
      };

      // Initialize collectors
      this.fingerprintCollector = new FingerprintCollector();
      this.sessionCollector = new SessionDataCollector();

      // Track SDK usage
      this.stats = {
        collectionsCount: 0,
        requestsCount: 0,
        errorsCount: 0
      };

      this._log('IDROCK SDK initialized', this.config);
    }

    /**
     * Collect risk data for assessment
     * This data is sent to NexShop backend, NOT directly to IDROCK API
     * 
     * @param {string} actionType - Type of action (login, checkout, sensitive_action)
     * @param {Object} additionalData - Additional context data
     * @returns {Promise<Object>} Collected risk data
     */
    async collectRiskData(actionType, additionalData = {}) {
      try {
        this.stats.collectionsCount++;

        const riskData = {
          action_type: actionType,
          timestamp: new Date().toISOString(),
          user_agent: navigator.userAgent,
          additional_data: additionalData
        };

        // Collect device fingerprint if enabled
        if (this.config.enableFingerprinting) {
          riskData.device_fingerprint = await this.fingerprintCollector.collect();
        }

        // Collect session data if enabled
        if (this.config.enableSessionTracking) {
          riskData.session_data = this.sessionCollector.collect();
        }

        this._log('Risk data collected', { actionType, dataKeys: Object.keys(riskData) });
        return riskData;

      } catch (error) {
        this.stats.errorsCount++;
        this._log('Risk data collection failed', error);
        return this._getFallbackData(actionType, additionalData);
      }
    }

    /**
     * Send collected data to NexShop backend
     * 
     * @param {Object} riskData - Collected risk data
     * @param {string} endpoint - Backend endpoint (optional)
     * @returns {Promise<Object>} Backend response
     */
    async sendToBackend(riskData, endpoint = '/assess') {
      try {
        this.stats.requestsCount++;

        const url = `${this.config.apiEndpoint}${endpoint}`;
        const response = await this._makeRequest(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(riskData)
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();
        this._log('Data sent to backend successfully', { endpoint: url });
        
        return result;

      } catch (error) {
        this.stats.errorsCount++;
        this._log('Failed to send data to backend', error);
        throw error;
      }
    }

    /**
     * Convenience method for login assessment
     * 
     * @param {string} username - Username for login
     * @param {Object} additionalData - Additional login context
     * @returns {Promise<Object>} Assessment response
     */
    async assessLogin(username, additionalData = {}) {
      const riskData = await this.collectRiskData('login', {
        username,
        ...additionalData
      });

      return this.sendToBackend(riskData, '/login-assess');
    }

    /**
     * Convenience method for checkout assessment
     * 
     * @param {Object} orderData - Order/checkout data
     * @returns {Promise<Object>} Assessment response
     */
    async assessCheckout(orderData) {
      const riskData = await this.collectRiskData('checkout', {
        order_amount: orderData.totalAmount,
        payment_method: orderData.paymentMethod,
        shipping_address: orderData.shippingAddress,
        item_count: orderData.itemCount || 1
      });

      return this.sendToBackend(riskData, '/checkout-assess');
    }

    /**
     * Get SDK statistics
     * 
     * @returns {Object} SDK usage statistics
     */
    getStats() {
      return {
        ...this.stats,
        config: {
          enableFingerprinting: this.config.enableFingerprinting,
          enableSessionTracking: this.config.enableSessionTracking,
          debug: this.config.debug
        }
      };
    }

    /**
     * Make HTTP request with timeout and retry
     * 
     * @private
     * @param {string} url - Request URL
     * @param {Object} options - Fetch options
     * @returns {Promise<Response>} Fetch response
     */
    async _makeRequest(url, options) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal
        });

        clearTimeout(timeoutId);
        return response;

      } catch (error) {
        clearTimeout(timeoutId);
        
        if (error.name === 'AbortError') {
          throw new Error('Request timeout');
        }
        
        throw error;
      }
    }

    /**
     * Get fallback data when collection fails
     * 
     * @private
     * @param {string} actionType - Action type
     * @param {Object} additionalData - Additional data
     * @returns {Object} Fallback risk data
     */
    _getFallbackData(actionType, additionalData) {
      return {
        action_type: actionType,
        timestamp: new Date().toISOString(),
        user_agent: navigator.userAgent || 'unknown',
        device_fingerprint: `fallback_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        session_data: {
          timestamp: new Date().toISOString(),
          fallback: true,
          url: window.location.href
        },
        additional_data: additionalData,
        fallback: true
      };
    }

    /**
     * Logging utility
     * 
     * @private
     * @param {string} message - Log message
     * @param {*} data - Additional data to log
     */
    _log(message, data = null) {
      if (this.config.debug) {
        console.log(`[IDROCK SDK] ${message}`, data);
      }
    }
  }

  // Export SDK to global scope or as module
  if (typeof module !== 'undefined' && module.exports) {
    // Node.js/CommonJS
    module.exports = IDRockSDK;
  } else if (typeof define === 'function' && define.amd) {
    // AMD
    define([], function() {
      return IDRockSDK;
    });
  } else {
    // Browser global
    window.IDRockSDK = IDRockSDK;
  }

})(typeof window !== 'undefined' ? window : global);