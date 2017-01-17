Ext.namespace('Zarafa.plugins.smime.dialogs');

/**
 * @class Zarafa.plugins.smime.dialogs.PassphraseWindow
 * @extends Zarafa.core.ui.ContentPanel
 *
 * The content panel which asks the user for his passphrase and verifies if it's correct.
 * @xtype smime.passphrasewindow
 */
Zarafa.plugins.smime.dialogs.PassphraseWindow = Ext.extend(Zarafa.core.ui.ContentPanel, {

	/**
	 * cfg {Ext.Button} btn the smime security dropdown button
	 */
	btn : undefined,

	/**
	 * @constructor
	 * @param config Configuration structure
	 */
	constructor : function(config) {
		config = config || {};

		this.btn = config.record;

		Ext.applyIf(config, {
			modal: true,
			width: 365,
			height: 55,
			title : _('S/MIME Passphrase', 'plugin_smime'),
			xtype: 'smime.passphrasewindow',
			cls : 'zarafa-smime-passphrasewindow',
			items: this.getInnerItems()
		});

		Zarafa.plugins.smime.dialogs.PassphraseWindow.superclass.constructor.call(this, config);
	},

	/**
	 * Helper function which provide necessary inner items based on the detected browser.
	 * There are different expectations from browser to prompt for password.
	 * @return {Array} returns array of the inner items which will be rendered
	 */
	getInnerItems : function()
	{
		var innerItems = [];
		var passwordSaveEnabled = container.getSettingsModel().get('zarafa/v1/plugins/smime/passphrase_cache');

		if (Ext.isGecko && passwordSaveEnabled) {
			innerItems.push({
				xtype : "component",
				autoEl : {
					tag : "iframe",
					style : "border-width: 0px;"
				},
				listeners : {
					render : this.onIframeRendered,
					scope : this
				}
			});
		} else if (Ext.isChrome && passwordSaveEnabled) {
			innerItems.push({
				xtype : 'form',
				labelAlign : 'left',
				height: 105,
				border : false,
				url : Ext.urlAppend(container.getBaseURL(), 'load=custom'),
				method : 'POST',
				items : [{
					xtype: 'textfield',
					inputType : 'text',
					name : 'username',
					hidden : true,
					value : container.getUser().getSMTPAddress()
				},{
					xtype: 'textfield',
					inputType: 'password',
					fieldLabel: _('Certificate passphrase', 'plugin_smime'),
					cls: 'certificate_passphrase',
					ref: '../passphrase',
					name : 'password',
					scope: this,
					listeners: {
						scope: this,
						specialkey: this.onSpecialKey
					}
				},{
					xtype: 'button',
					text:  _('Submit', 'plugin_smime'),
					cls: 'passphrase-submit  zarafa-action',
					handler: this.checkPassphrase,
					scope: this,
					width: 100,
					minWidth: 100
				}]
			});
		} else {
			innerItems.push({
				xtype : 'container',
				layout : 'form',
				items : [{
					xtype: 'textfield',
					inputType: 'password',
					fieldLabel: _('Certificate passphrase', 'plugin_smime'),
					cls: 'certificate_passphrase',
					ref: '../passphrase',
					scope: this,
					listeners: {
						scope: this,
						specialkey: this.onSpecialKey
					}
				},{
					xtype: 'button',
					text:  _('Submit', 'plugin_smime'),
					cls: 'passphrase-submit zarafa-action',
					handler: this.checkPassphrase,
					scope: this,
					width: 100,
					minWidth: 100
				}]
			});
		}

		return innerItems;
	},

	/**
	 * Handler function which executes after the {@link Ext.Component} gets rendered.
	 * This will generate and add a form element along with necessary form-items into
	 * the underlying iframe element.
	 * @param {Ext.Component|HTMLElement} component which gets rendered into this window
	 */
	onIframeRendered : function(component) {
		var iframeElement = Ext.isDefined(component.getEl) ? component.el : component;

		Ext.EventManager.on(iframeElement, 'load', this.onIframeLoad.createDelegate(this));

		var innerHtmlStructure = "<form id='dynamicFormElement' action='" + Ext.urlAppend(container.getBaseURL(), 'load=custom') + "' method='POST' style='font: 13px arial;'>" +
				"<input type='text' name='username' value='" + container.getUser().getSMTPAddress() + "' style='display:none'>" +
				"<div style='float:left;width:130px'>" +
					"<label for='dynamicPasswordElement'>" + _('Certificate passphrase', 'plugin_smime') + ":" + "</label>" +
				"</div>" +
				"<div style='float:right;'>" +
					"<input type='password' name='spassword' autocomplete='on' id='dynamicPasswordElement'>" +
				"</div>" +
				"<br><br>" +
				"<input type='submit' value='" + _('Submit', 'plugin_smime') + "' style='display:inline-block;border:none;height:auto;border-radius:0;box-shadow: 0px 1px 1px 0px;background:#e6e6e6;margin:30px 0 0 0;cursor: pointer;padding: 0 6px;'>" +
			"</form>";

		var iframeDom = Ext.isDefined(iframeElement.dom) ? iframeElement.dom : iframeElement;
		iframeDom.contentDocument.write(innerHtmlStructure);
	},

	/**
	 * Handler for the 'load' event of iframe, fired after iframe is loaded.
	 * The response is received in json format, so we are using {@link Ext.util.JSON#decode}
	 * to decode (parse) a JSON string to an object.
	 * Then relay the response object to response handler.
	 * @param {Ext.EventObject} event The event information
	 * @param {Ext.Component} evtTarget The component for which this event gets fired
	 */
	onIframeLoad : function(event, evtTarget)
	{
		var iframeBody = evtTarget.contentDocument.body;
		if(!Ext.isEmpty(iframeBody.textContent)) {
			var responseobj = Ext.util.JSON.decode(iframeBody.textContent);
			if (responseobj.status === true) {
				this.onPassphraseCallback(responseobj);
			} else {
				this.onIframeRendered(evtTarget);
			}
		}
	},

	/**
	 * Function which checks if the user inputs an enter in the password textfield
	 * And then checks if a valid passphrase has been entered. 
	 * @param {Ext.form.TextField} field
	 * @param {Ext.EventObject} eventobj
	 */
	onSpecialKey : function(field, eventobj)
	{
		if(eventobj.getKey() === eventobj.ENTER) {
			this.checkPassphrase();
		}
	},

	/**
	 * Function which calls a request to PHP which verifies if the supplied passphrase is correct.
	 * Calls onPassphraseCallback if there is a succesCallback.
	 * @param {Ext.button} button submit button of the form
	 */
	checkPassphrase : function(button) {
		var user = container.getUser();
		container.getRequest().singleRequest(
			'pluginsmimemodule',
			'passphrase',
			{ 
			  'user' : user.getSMTPAddress(),
			  'sessionid' : user.getSessionId(),
			  'passphrase' : this.passphrase.getValue()
			},
			new Zarafa.plugins.smime.data.SmimeResponseHandler({
				successCallback : this.onPassphraseCallback.createDelegate(this)
			})
		);
	},

	/**
	 * successCallback function for the request to verify if a private certificate passphrase is correct
	 * If the response status is true, the contentpanel will be closed and the record message_class will be set 
	 * and the record is saved.
	 * Otherwise the inputfield will be reset.
	 * @param {Object} response Json object containing the response from PHP
	 */
	onPassphraseCallback : function(response) {
		if(response.status) {
			if(this.btn instanceof Zarafa.core.data.IPMRecord) {
				this.btn.open({forceLoad: true});
			} else {
				var owner = this.btn.ownerCt;
				var record = owner.record;
				record.set('message_class', this.btn.message_class);
				record.save();
				this.btn.setIconClass('icon_smime_sign_selected');
			}
			this.close();
		} else {
			if(this.passphrase) {
				this.passphrase.reset();
			}
			container.getNotifier().notify('error.connection', _('S/MIME Message', 'plugin_smime'), _('Password incorrect', 'plugin_smime'));
		}
	}
});

Ext.reg('smime.passphrasewindow', Zarafa.plugins.smime.dialogs.PassphraseWindow);
