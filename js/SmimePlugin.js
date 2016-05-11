Ext.namespace('Zarafa.plugins.smime');

/**
 * @class Zarafa.plugins.smime.SmimePlugin
 * @extends Zarafa.core.Plugin
 */
Zarafa.plugins.smime.SmimePlugin = Ext.extend(Zarafa.core.Plugin, {
	/*
	 * Called after constructor.
	 * Registers insertion points.
	 * @protected
	 */
	initPlugin : function()
	{	
		Zarafa.plugins.smime.SmimePlugin.superclass.initPlugin.apply(this, arguments);

		// S/MIME button in mailcreatecontentpanel
		this.registerInsertionPoint('context.mail.mailcreatecontentpanel.toolbar.options', this.showSignButton, this);
		this.registerInsertionPoint('context.mail.mailcreatecontentpanel.toolbar.options', this.showEncryptButton, this);

		// S/MIME Settings widget insertion point
		this.registerInsertionPoint('context.settings.categories', this.createSettingsCategories, this);

		// Insertion point which shows the verified/decrypted status
		this.registerInsertionPoint('previewpanel.toolbar.detaillinks', this.showSmimeInfo, this);

		// S/MIME Icons
		this.registerInsertionPoint('context.mail.gridrow', this.showMessageClass , this);
		this.registerInsertionPoint('context.mail.griddefaultcolumn', this.showDefaultColumn, this);
			
		Zarafa.core.data.SharedComponentType.addProperty('plugin.smime.dialog.passphrasewindow');
	},

	/**
	 * Create a category in settings for S/MIME
	 *
	 * @return {smimesettingscategory} 
	 */
	createSettingsCategories : function(insertionName, settingsMainPanel, settingsContext) 
	{
		return [{
			xtype : 'smime.settingssmimecategory',
			settingsContext: settingsContext
		}];
	},

	/**
	 * Displays S/MIME information in the previewpanel  
	 *
	 * @return {Object} a box which on record update displays S/MIME information
	 */
	showSmimeInfo : function() 
	{
		return {
			xtype: 'button',
			plugins : [ 'zarafa.recordcomponentupdaterplugin' ],
			autoEl: {
				tag: 'div',
				ref: 'smimeInfoBox'
			},
			scope : this,
			update : this.onSmimeInfo,
			handler : this.onSmimeButton
		};
	},

	/**
	 * Create button which sets the MessageClass to IPM.Note.SMIME.MultiPartSigned
	 * when creating an email.
	 * If certificate is unlocked we can display the Sign button, else a blank label
	 *
	 * @return {Config} creates a button for signing email
	 */
	showSignButton : function() 
	{
		return {
			xtype : 'button',
			text : _('Sign', 'plugin_smime'),
			tooltip: {
				title: _('Sign message', 'plugin_smime'),
				text: _('Ensure the authenticity of the message by adding a digital signature to this message. Any changes to the message will invalidate the signature.', 'plugin_smime')
			},
			iconCls : 'icon_smime_sign',
			handler : this.onSignButton,
			scope : this
		};
	},

	/**
	 * Create button which sets the MessageClass to IPM.Note.SMIME
	 * when creating an email in context.mail.mailcreatecontentpanel.toolbar.option
	 *
	 * @return {Object} creates a button for encrypting an email
	 */
	showEncryptButton : function() 
	{
		return {
			xtype : 'button',
			text : _('Encrypt', 'plugin_smime'),
			tooltip: {
				title: _('Encrypt message', 'plugin_smime'),
				text: _('Ensure the privacy of the message by encrypting its contents. Only the recipient of the message will be able to open it.', 'plugin_smime')
			},
			iconCls : 'icon_smime_encrypt',
			handler : this.onEncryptButton,
			scope : this
		};
	},

	/**
	 * Handler for the button which is displayed when a encrypted / signed message is openend
	 * When an encrypted message is opened, we will send a request to unlock the certificate.
	 * When an signed email is openend, we will show a popup with extra information about the signed message
	 */
	onSmimeButton: function(button, config)
	{
		var smimeInfo = button.record.get('smime');
		if(button.record.isOpened() && smimeInfo) {
			switch(smimeInfo.type) {
				case 'encrypted':
					if (smimeInfo.success !== Zarafa.plugins.smime.SMIME_STATUS_GOOD) {
						var user = container.getUser();
						container.getRequest().singleRequest(
							'pluginsmimemodule',
							'certificate',
							{ 
							  'user' : user.getSMTPAddress(),
							  'sessionid' : user.getSessionId()
							},
							new Zarafa.plugins.smime.data.SmimeResponseHandler({
								successCallback : this.onCertificateCallback.createDelegate(button.record)
							})
						);
					}
					break;
				case 'signed':
				case 'encryptsigned':
					container.getNotifier().notify(Zarafa.plugins.smime.SmimeText.getPopupStatus(smimeInfo.success), 
							_('What\'s going on with my email?', 'plugin_smime'), Zarafa.plugins.smime.SmimeText.getPopupText(smimeInfo.info));
					break;
			}
		}
	},

	/**
	 * Function which displays information in the previewpanel.
	 * In the case of a encrypted message, we either show a button to unlock the certificate
	 * or shows the message that the message has been decrypted.
	 * If the message is signed we display information depending on the state of the verification.
	 * 
	 * @param {Zarafa.core.data.IPMRecord} record record which is displayed
	 * @param {Boolean} contentReset force the component to perform a full update of the data.
	 */
	onSmimeInfo : function(record, resetContent) 
	{
		// Set button.record for use in onSmimeButton
		this.record = record;
		var smimeInfoBox = this.getEl();
		
		// Set smimeBox to empty value by default, to override previous S/MIME message text
		smimeInfoBox.update("");
		smimeInfoBox.removeClass('smime-info-good');
		smimeInfoBox.removeClass('smime-info-fatal');
		smimeInfoBox.removeClass('smime-info-partial');

		// retrieve smime json object
		var smimeInfo = record.get('smime');
		if(record.isOpened() && smimeInfo) {
			var sender = record.getSender();

			// FIXME: refactor success, to status since that's probably a better description of the variable
			smimeInfoBox.addClass(Zarafa.plugins.smime.SmimeText.getStatusMessageClass(smimeInfo.success));
			var message = Zarafa.plugins.smime.SmimeText.getMessageInfo(smimeInfo.info);
			switch(smimeInfo.type) {
				case 'encrypted':
					// Empty smimeInfoBox
					if( smimeInfo.success === Zarafa.plugins.smime.SMIME_STATUS_BAD) {
						smimeInfoBox.update('<div class="icon_smime_encr_content"></div> ' + message);
					} else {
						smimeInfoBox.update(String.format(' {0} &lt{1}&gt <div class="icon_smime_decr_content"></div> {2}', sender.get('display_name'), sender.get('smtp_address'), message));
						// Force the Attachmentlinks component to update, to view the attachments
						this.ownerCt.findByType('zarafa.attachmentlinks')[0].update(record, true);
					}
					break;
				case 'signed':
					smimeInfoBox.update(String.format('{0} &lt{1}&gt <div class="icon_smime_sign_content"></div> {2}', sender.get('display_name'), sender.get('smtp_address'), message));
					break;
				case 'encryptsigned':
					smimeInfoBox.update(String.format('{0} &lt{1}&gt <div class="icon_smime_sign_content"></div> <div class="icon_smime_decr_content"></div> {2}', sender.get('display_name'), sender.get('smtp_address'), message));
					if(smimeInfo.success !== Zarafa.plugins.smime.SMIME_STATUS_BAD) {
						// Force the Attachmentlinks component to update, to view the attachments
						this.ownerCt.findByType('zarafa.attachmentlinks')[0].update(record, true);
					}
					break;
			}
		}
	},

	/**
	 * Function which collects all the recipients smtp_addresses in a list and sets them as 'smime'
	 * property in the mailrecord. Because the hook in PHP doesn't have updated recipienttable yet.
	 *
	 * @param {Zarafa.mailcreatecontentpanel} dialog 
	 * @param {Zarfa.core.data.IPMRecord} record The record which is going to be send
	 * @return {Boolean} returns false if public key isn't find and stops the record from being send
	 *
	 */
	onBeforeSendRecord : function(dialog, record) {
		// Get list of recipients and set them in the 'smime' property
		var recipientStore = record.getRecipientStore();
		var recipients = [];
		recipientStore.each(function(recip) {
			recipients.push(recip.get('smtp_address'));
		}, this);
		dialog.record.set('smime', recipients);

		return true;
	},

	/**
	 * Handler for the encrypt button, when clicked it sets the message_class to encrypted.
	 * If we press the button again we reset the message_class. When a user already has signed an email
	 * we set a special message_class on it to sign+encrypt
	 *
	 * @param {Ext.button} button
	 * @param {Object} config
	 */
	onEncryptButton : function(button, config) 
	{
		var owner = button.ownerCt;
		var record = owner.record;
		if(record) {
			switch(record.get('message_class')) {
				// Sign and Encrypt
				case 'IPM.Note.SMIME.MultipartSigned':
					record.set('message_class', 'IPM.Note.SMIME.SignedEncrypt');
					button.setIconClass('icon_smime_encrypt_selected');

					// Add event to check if all recipients have a public key
					owner.dialog.on('beforesendrecord', this.onBeforeSendRecord ,this);
					break;
				// We want to encrypt
				case 'IPM.Note': 
					button.setIconClass('icon_smime_encrypt_selected');
					record.set('message_class', 'IPM.Note.SMIME');

					// Add event to check if all recipients have a public key
					owner.dialog.on('beforesendrecord', this.onBeforeSendRecord ,this);
					break;
				// Unselecting encrypt functionality
				case 'IPM.Note.SMIME': 
				case 'IPM.Note.SMIME.SignedEncrypt':
					if (record.get('message_class') === 'IPM.Note.SMIME.SignedEncrypt') {
						record.set('message_class', 'IPM.Note.SMIME.MultipartSigned');
					} else {
						record.set('message_class', 'IPM.Note');
					}

					button.setIconClass('icon_smime_encrypt');
					// Reset smime property
					record.set('smime','')
					// Reset send action, otherwise the saveRecord will trigger a send when the user deselects encryption
					record.actions = {}

					// Remove event
					owner.dialog.un('beforesendrecord', this.onBeforeSendRecord ,this);
					break;
			}
			owner.dialog.saveRecord();
		}
	},

	/**
	 * Handler for the sign button, when clicked it checks if the private certificate exists.
	 * If we have signing already set and click it again, we unset it.
	 * If we already set have encryption set, we set a special message_class for both sign+ecnrypt.
	 *
	 *
	 * @param {Ext.button} button
	 * @param {Object} config
	 */
	onSignButton : function(button, config) 
	{
		var owner = button.ownerCt;
		var record = owner.record;
		if(record) {
			var plugin = this;
			var user = container.getUser();
			var request = function() {
				container.getRequest().singleRequest(
					'pluginsmimemodule',
					'certificate',
					{ 
					  'user' : user.getSMTPAddress(),
					  'sessionid' : user.getSessionId()
					},
					new Zarafa.plugins.smime.data.SmimeResponseHandler({
						successCallback : plugin.onCertificateCallback.createDelegate(button)
					})
				);
			}
			switch(record.get('message_class')) {
				// We want to sign
				case 'IPM.Note':
					button.message_class = 'IPM.Note.SMIME.MultipartSigned';
					request();
					break;
				// Encrypt + Sign
				case 'IPM.Note.SMIME':
					button.message_class = 'IPM.Note.SMIME.SignedEncrypt';
					request();
					break;
				case 'IPM.Note.SMIME.MultipartSigned':
					button.setIconClass('icon_smime_sign');
					record.set('message_class', 'IPM.Note');
					break;
				case 'IPM.Note.SMIME.SignedEncrypt':
					button.setIconClass('icon_smime_sign');
					record.set('message_class', 'IPM.Note.SMIME');
					break;
			}
		}
		owner.dialog.saveRecord();
	},

	/**
	 * successCallback function for the request to verify if a private certificate exists in the mapi userstore.
	 * If the response status is true the certificate exists and we will query the user for his passphrase.
	 *
	 * @param {Object} response Json object containing the response from PHP
	 */
	onCertificateCallback : function(response) {
		// TODO: improve functionality with less callbacks
		var btn = this;
		if(response.status) { 
		    	Zarafa.core.data.UIFactory.openLayerComponent(Zarafa.core.data.SharedComponentType['plugin.smime.dialog.passphrasewindow'], btn, {manager: Ext.WindowMgr});
		} else {
			container.getNotifier().notify('info.saved', _('S/MIME Message', 'plugin_smime'), response.message);
		}
	},

	/*
	 * Bid for the type of shared component
	 * and the given record.
	 * This will bid on calendar.dialogs.importevents
	 * @param {Zarafa.core.data.SharedComponentType} type Type of component a context can bid for.
	 * @param {Zarafa.mail.dialogs.MailCreateContentPanel} owner Optionally passed panel
	 * @return {Number} The bid for the shared component
	 */
	bidSharedComponent : function(type, record) {
		var bid = -1;

		switch(type) {
			case Zarafa.core.data.SharedComponentType['plugin.smime.dialog.passphrasewindow']:
				bid = 1;
				break;
		}
		return bid;
	},

	/**
	 * Will return the reference to the shared component.
	 * Based on the type of component requested a component is returned.
	 * @param {Zarafa.core.data.SharedComponentType} type Type of component a context can bid for.
	 * @param {Zarafa.mail.dialogs.MailCreateContentPanel} owner Optionally passed panel
	 * @return {Ext.Component} Component
	 */
	getSharedComponent : function(type, record) {
		var component;

		switch(type) {
			case Zarafa.core.data.SharedComponentType['plugin.smime.dialog.passphrasewindow']:
				component = Zarafa.plugins.smime.dialogs.PassphraseWindow;
				break;
		}

		return component;
	},

	/**
	 * Shows the message class icon of signed or encrypted email in the defaultcolumn
	 *
	 * @param {string} insertionPoint name of insertion point
	 * @param {Zarafa.core.data.IPMRecord} record The record of a row
	 *
	 */
	showDefaultColumn : function(insertionPoint, record) 
	{
		return  {
			header : _('SMIME Message', 'plugin_smime'),
			dataIndex : 'message_class',
			width : 12,
			sortable : false,
			renderer :  function(value, p, record) { 
				var messageClass = record.get('message_class'); 
				if(messageClass == 'IPM.Note.SMIME') {
					p.css = 'icon_smime_encrypt'; 
				} else if(messageClass == 'IPM.Note.SMIME.MultipartSigned') {
					p.css = 'icon_smime_sign'; 
				}
				return ''; 
			},
			fixed : true,
			tooltip : _('S/MIME Message', 'plugin_smime')
		};
	},

	/**
	 * Shows the message class icon of signed or encrypted email in the non defaultcolumn
	 *
	 * @param {string} insertionPoint name of insertion point
	 * @param {Zarafa.core.data.IPMRecord} record The record of a row
	 * @return {string} column entry
	 *
	 */
	showMessageClass : function(insertionPoint, record) { 
		var messageClass = record.get('message_class');
		var icon = "";
		if(messageClass == 'IPM.Note.SMIME') {
			icon = 'icon_smime_encrypt';
		} 
		else if(messageClass == 'IPM.Note.SMIME.MultipartSigned') {
			icon = 'icon_smime_sign';
		}
		return String.format('<td style="width: 24px"><div class="grid_compact {0}" style="height: 24px; width: 24px;">{1}</div></td>', icon, "");
	}
});

// Add property to record to MailRecord, where extra information is stored about S/MIME messages
Zarafa.core.data.RecordFactory.addFieldToMessageClass('IPM.Note', [{name: 'smime', defaultValue: ''}]);

Zarafa.onReady(function() {
	Zarafa.plugins.smime.SMIME_STATUS_GOOD = 0;
	Zarafa.plugins.smime.SMIME_STATUS_PARTIAL = 2;
	Zarafa.plugins.smime.SMIME_STATUS_FATAL = 2;

	container.registerPlugin(new Zarafa.core.PluginMetaData({
		name : 'smime',
		displayName : _('S/MIME Plugin', 'plugin_smime'),
		pluginConstructor : Zarafa.plugins.smime.SmimePlugin
	}));
});
