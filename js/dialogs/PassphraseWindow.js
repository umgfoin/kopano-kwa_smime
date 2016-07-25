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
			layout : 'form',
			modal: true,
			width: 365,
			height: 105,
			title : _('S/MIME Passphrase', 'plugin_smime'),
			xtype: 'smime.passphrasewindow',
			cls : 'zarafa-smime-passphrasewindow',
			items: [{
				xtype: 'textfield',
				inputType: 'password',
				fieldLabel: _('Certificate passphrase', 'plugin_smime'),
				cls: 'certificate_passphrase',
				ref: 'passphrase',
				scope: this,
				listeners: {
					scope: this,
					specialkey: this.onSpecialKey
				}
			},{
				xtype: 'button',
				text:  _('Submit', 'plugin_smime'),
				cls: 'passphrase_submit',
				handler: this.checkPassphrase,
				scope: this,
				width: 100,
				minWidth: 100
			}]
		});
		Zarafa.plugins.smime.dialogs.PassphraseWindow.superclass.constructor.call(this, config);
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
				this.btn.setIconClass('icon_smime_sign_selected')
			}
			this.close();
		} else {
			this.passphrase.reset();
			container.getNotifier().notify('error.connection', _('S/MIME Message', 'plugin_smime'), _('Password incorrect', 'plugin_smime'));
		}
	}
});

Ext.reg('smime.passphrasewindow', Zarafa.plugins.smime.dialogs.PassphraseWindow);
