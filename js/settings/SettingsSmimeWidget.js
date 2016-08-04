Ext.namespace('Zarafa.plugins.smime.settings');
/**
 * @class Zarafa.plugins.smime.settings.SettingsSmimeWidget
 * @extends Zarafa.settings.ui.SettingsWidget
 * @xtype smime.settingssmimewidget
 *
 * The {@link Zarafa.plugins.settings.SettingsSmimeWidget widget} for importing S/MIME certificates (public/private)
 */
Zarafa.plugins.smime.settings.SettingsSmimeWidget = Ext.extend(Zarafa.settings.ui.SettingsWidget, {

	/**
	 * @cfg {Zarafa.core.data.IPMRecord} record.
	 */
	record : undefined,

	/**
	 * @constructor
	 * @param {Object} config Configuration object
	 */
	constructor : function(config) {
		config = config || {};

		if(!config.store) {
			config.store = new Zarafa.plugins.smime.data.SmimeCertificateStore();
		}

		Ext.applyIf(config, {
			title	: _('Personal certificate', 'plugin_smime'),
			layout : 'form',
			xtype : 'smime.settingssmimewidget',
			items :[{
				xtype: 'displayfield',
				ref: 'certificateField',
				hideLabel : true,
				defaultValue : _('You don\'t have a valid certificate corresponding to your account', 'plugin_smime')
			}]
		});

		Zarafa.plugins.smime.settings.SettingsSmimeWidget.superclass.constructor.call(this, config);
	},


	/**
	 * initialize events for the grid panel.
	 * @private
	 */
	initEvents : function()
	{
		Zarafa.plugins.smime.settings.SettingsSmimeWidget.superclass.initEvents.call(this);
		// TODO: shouldn't this be update?
		this.mon(this.store, 'load', this.onStoreReady, this);
		this.mon(this.store, 'remove', this.onStoreReady, this);
		this.onStoreReady();
	},

	/**
	 * Event handler which is fired when the store is loaded or an item is removed from the store
	 * @private
	 */
	onStoreReady : function()
	{
		var index = this.store.findExact('type', 'private');
		if(index === -1) {
			this.certificateField.setRawValue(this.certificateField.defaultValue);
		} else {
			this.record = this.store.getAt(index);
			// TODO: add validity message
			this.certificateField.setRawValue(_('You have a valid certificate corresponding to your account', 'plugin_smime'));
		}
	}
});

Ext.reg('smime.settingssmimewidget', Zarafa.plugins.smime.settings.SettingsSmimeWidget);
