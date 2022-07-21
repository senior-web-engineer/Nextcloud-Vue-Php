/******/ (function() { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./core/src/logger.js":
/*!****************************!*\
  !*** ./core/src/logger.js ***!
  \****************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _nextcloud_auth__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @nextcloud/auth */ "./node_modules/@nextcloud/auth/dist/index.js");
/* harmony import */ var _nextcloud_logger__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @nextcloud/logger */ "./node_modules/@nextcloud/logger/dist/index.js");
/**
 * @copyright 2019 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @author Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @license AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */



var getLogger = function getLogger(user) {
  if (user === null) {
    return (0,_nextcloud_logger__WEBPACK_IMPORTED_MODULE_1__.getLoggerBuilder)().setApp('core').build();
  }

  return (0,_nextcloud_logger__WEBPACK_IMPORTED_MODULE_1__.getLoggerBuilder)().setApp('core').setUid(user.uid).build();
};

/* harmony default export */ __webpack_exports__["default"] = (getLogger((0,_nextcloud_auth__WEBPACK_IMPORTED_MODULE_0__.getCurrentUser)()));

/***/ }),

/***/ "./core/src/profile.js":
/*!*****************************!*\
  !*** ./core/src/profile.js ***!
  \*****************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var vue__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! vue */ "./node_modules/vue/dist/vue.runtime.esm.js");
/* harmony import */ var _nextcloud_auth__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @nextcloud/auth */ "./node_modules/@nextcloud/auth/dist/index.js");
/* harmony import */ var _nextcloud_l10n__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @nextcloud/l10n */ "./node_modules/@nextcloud/l10n/dist/index.js");
/* harmony import */ var v_tooltip__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! v-tooltip */ "./node_modules/v-tooltip/dist/v-tooltip.esm.js");
/* harmony import */ var _logger__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./logger */ "./core/src/logger.js");
/* harmony import */ var _views_Profile__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./views/Profile */ "./core/src/views/Profile.vue");
/**
 * @copyright 2021, Christopher Ng <chrng8@gmail.com>
 *
 * @author Christopher Ng <chrng8@gmail.com>
 *
 * @license AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */






__webpack_require__.nc = btoa((0,_nextcloud_auth__WEBPACK_IMPORTED_MODULE_0__.getRequestToken)());
vue__WEBPACK_IMPORTED_MODULE_5__["default"].use(v_tooltip__WEBPACK_IMPORTED_MODULE_2__["default"]);
vue__WEBPACK_IMPORTED_MODULE_5__["default"].mixin({
  props: {
    logger: _logger__WEBPACK_IMPORTED_MODULE_3__["default"]
  },
  methods: {
    t: _nextcloud_l10n__WEBPACK_IMPORTED_MODULE_1__.translate
  }
});
var View = vue__WEBPACK_IMPORTED_MODULE_5__["default"].extend(_views_Profile__WEBPACK_IMPORTED_MODULE_4__["default"]);
new View().$mount('#vue-profile');

/***/ }),

/***/ "./node_modules/babel-loader/lib/index.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=script&lang=js&":
/*!******************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/babel-loader/lib/index.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=script&lang=js& ***!
  \******************************************************************************************************************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
/* harmony default export */ __webpack_exports__["default"] = ({
  name: 'PrimaryActionButton',
  props: {
    disabled: {
      type: Boolean,
      default: false
    },
    href: {
      type: String,
      required: true
    },
    icon: {
      type: String,
      required: true
    },
    target: {
      type: String,
      required: true,
      validator: function validator(value) {
        return ['_self', '_blank', '_parent', '_top'].includes(value);
      }
    }
  },
  computed: {
    colorPrimaryText: function colorPrimaryText() {
      // For some reason the returned string has prepended whitespace
      return getComputedStyle(document.body).getPropertyValue('--color-primary-text').trim();
    }
  }
});

/***/ }),

/***/ "./node_modules/babel-loader/lib/index.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=script&lang=js&":
/*!*****************************************************************************************************************************************************************!*\
  !*** ./node_modules/babel-loader/lib/index.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=script&lang=js& ***!
  \*****************************************************************************************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _nextcloud_auth__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @nextcloud/auth */ "./node_modules/@nextcloud/auth/dist/index.js");
/* harmony import */ var _nextcloud_event_bus__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @nextcloud/event-bus */ "./node_modules/@nextcloud/event-bus/dist/index.js");
/* harmony import */ var _nextcloud_initial_state__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @nextcloud/initial-state */ "./node_modules/@nextcloud/initial-state/dist/index.js");
/* harmony import */ var _nextcloud_router__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @nextcloud/router */ "./node_modules/@nextcloud/router/dist/index.js");
/* harmony import */ var _nextcloud_dialogs__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @nextcloud/dialogs */ "./node_modules/@nextcloud/dialogs/dist/index.es.js");
/* harmony import */ var _nextcloud_vue_dist_Components_Avatar__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @nextcloud/vue/dist/Components/Avatar */ "./node_modules/@nextcloud/vue/dist/Components/Avatar.js");
/* harmony import */ var _nextcloud_vue_dist_Components_Avatar__WEBPACK_IMPORTED_MODULE_5___default = /*#__PURE__*/__webpack_require__.n(_nextcloud_vue_dist_Components_Avatar__WEBPACK_IMPORTED_MODULE_5__);
/* harmony import */ var _nextcloud_vue_dist_Components_Actions__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! @nextcloud/vue/dist/Components/Actions */ "./node_modules/@nextcloud/vue/dist/Components/Actions.js");
/* harmony import */ var _nextcloud_vue_dist_Components_Actions__WEBPACK_IMPORTED_MODULE_6___default = /*#__PURE__*/__webpack_require__.n(_nextcloud_vue_dist_Components_Actions__WEBPACK_IMPORTED_MODULE_6__);
/* harmony import */ var _nextcloud_vue_dist_Components_ActionLink__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! @nextcloud/vue/dist/Components/ActionLink */ "./node_modules/@nextcloud/vue/dist/Components/ActionLink.js");
/* harmony import */ var _nextcloud_vue_dist_Components_ActionLink__WEBPACK_IMPORTED_MODULE_7___default = /*#__PURE__*/__webpack_require__.n(_nextcloud_vue_dist_Components_ActionLink__WEBPACK_IMPORTED_MODULE_7__);
/* harmony import */ var vue_material_design_icons_MapMarker__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! vue-material-design-icons/MapMarker */ "./node_modules/vue-material-design-icons/MapMarker.vue");
/* harmony import */ var vue_material_design_icons_Pencil__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! vue-material-design-icons/Pencil */ "./node_modules/vue-material-design-icons/Pencil.vue");
/* harmony import */ var vue_material_design_icons_Account__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! vue-material-design-icons/Account */ "./node_modules/vue-material-design-icons/Account.vue");
/* harmony import */ var _components_Profile_PrimaryActionButton__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ../components/Profile/PrimaryActionButton */ "./core/src/components/Profile/PrimaryActionButton.vue");
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//
//












var status = (0,_nextcloud_initial_state__WEBPACK_IMPORTED_MODULE_2__.loadState)('core', 'status', {});

var _loadState = (0,_nextcloud_initial_state__WEBPACK_IMPORTED_MODULE_2__.loadState)('core', 'profileParameters', {
  userId: null,
  displayname: null,
  address: null,
  organisation: null,
  role: null,
  headline: null,
  biography: null,
  actions: [],
  isUserAvatarVisible: false
}),
    userId = _loadState.userId,
    displayname = _loadState.displayname,
    address = _loadState.address,
    organisation = _loadState.organisation,
    role = _loadState.role,
    headline = _loadState.headline,
    biography = _loadState.biography,
    actions = _loadState.actions,
    isUserAvatarVisible = _loadState.isUserAvatarVisible;

/* harmony default export */ __webpack_exports__["default"] = ({
  name: 'Profile',
  components: {
    AccountIcon: vue_material_design_icons_Account__WEBPACK_IMPORTED_MODULE_10__["default"],
    ActionLink: (_nextcloud_vue_dist_Components_ActionLink__WEBPACK_IMPORTED_MODULE_7___default()),
    Actions: (_nextcloud_vue_dist_Components_Actions__WEBPACK_IMPORTED_MODULE_6___default()),
    Avatar: (_nextcloud_vue_dist_Components_Avatar__WEBPACK_IMPORTED_MODULE_5___default()),
    MapMarkerIcon: vue_material_design_icons_MapMarker__WEBPACK_IMPORTED_MODULE_8__["default"],
    PencilIcon: vue_material_design_icons_Pencil__WEBPACK_IMPORTED_MODULE_9__["default"],
    PrimaryActionButton: _components_Profile_PrimaryActionButton__WEBPACK_IMPORTED_MODULE_11__["default"]
  },
  data: function data() {
    return {
      status: status,
      userId: userId,
      displayname: displayname,
      address: address,
      organisation: organisation,
      role: role,
      headline: headline,
      biography: biography,
      actions: actions,
      isUserAvatarVisible: isUserAvatarVisible
    };
  },
  computed: {
    isCurrentUser: function isCurrentUser() {
      var _getCurrentUser;

      return ((_getCurrentUser = (0,_nextcloud_auth__WEBPACK_IMPORTED_MODULE_0__.getCurrentUser)()) === null || _getCurrentUser === void 0 ? void 0 : _getCurrentUser.uid) === this.userId;
    },
    allActions: function allActions() {
      return this.actions;
    },
    primaryAction: function primaryAction() {
      if (this.allActions.length) {
        return this.allActions[0];
      }

      return null;
    },
    middleActions: function middleActions() {
      if (this.allActions.slice(1, 4).length) {
        return this.allActions.slice(1, 4);
      }

      return null;
    },
    otherActions: function otherActions() {
      if (this.allActions.slice(4).length) {
        return this.allActions.slice(4);
      }

      return null;
    },
    settingsUrl: function settingsUrl() {
      return (0,_nextcloud_router__WEBPACK_IMPORTED_MODULE_3__.generateUrl)('/settings/user');
    },
    colorMainBackground: function colorMainBackground() {
      // For some reason the returned string has prepended whitespace
      return getComputedStyle(document.body).getPropertyValue('--color-main-background').trim();
    },
    emptyProfileMessage: function emptyProfileMessage() {
      return this.isCurrentUser ? t('core', 'You have not added any info yet') : t('core', '{user} has not added any info yet', {
        user: this.displayname || this.userId
      });
    }
  },
  mounted: function mounted() {
    // Set the user's displayname or userId in the page title and preserve the default title of "Nextcloud" at the end
    document.title = "".concat(this.displayname || this.userId, " - ").concat(document.title);
    (0,_nextcloud_event_bus__WEBPACK_IMPORTED_MODULE_1__.subscribe)('user_status:status.updated', this.handleStatusUpdate);
  },
  beforeDestroy: function beforeDestroy() {
    (0,_nextcloud_event_bus__WEBPACK_IMPORTED_MODULE_1__.unsubscribe)('user_status:status.updated', this.handleStatusUpdate);
  },
  methods: {
    handleStatusUpdate: function handleStatusUpdate(status) {
      if (this.isCurrentUser && status.userId === this.userId) {
        this.status = status;
      }
    },
    openStatusModal: function openStatusModal() {
      var statusMenuItem = document.querySelector('.user-status-menu-item__toggle'); // Changing the user status is only enabled if you are the current user

      if (this.isCurrentUser) {
        if (statusMenuItem) {
          statusMenuItem.click();
        } else {
          (0,_nextcloud_dialogs__WEBPACK_IMPORTED_MODULE_4__.showError)(t('core', 'Error opening the user status modal, try hard refreshing the page'));
        }
      }
    }
  }
});

/***/ }),

/***/ "./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true&":
/*!************************************************************************************************************************************************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true& ***!
  \************************************************************************************************************************************************************************************************************************************************************************************************************************/
/***/ (function(module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../../node_modules/css-loader/dist/runtime/noSourceMaps.js */ "./node_modules/css-loader/dist/runtime/noSourceMaps.js");
/* harmony import */ var _node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../../node_modules/css-loader/dist/runtime/api.js */ "./node_modules/css-loader/dist/runtime/api.js");
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__);
// Imports


var ___CSS_LOADER_EXPORT___ = _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default()((_node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default()));
// Module
___CSS_LOADER_EXPORT___.push([module.id, ".profile__primary-action-button[data-v-cdc2cc30] {\n  font-size: var(--default-font-size);\n  font-weight: bold;\n  width: 188px;\n  height: 44px;\n  padding: 0 16px;\n  line-height: 44px;\n  text-align: center;\n  border-radius: var(--border-radius-pill);\n  color: var(--color-primary-text);\n  background-color: var(--color-primary-element);\n  overflow: hidden;\n  white-space: nowrap;\n  text-overflow: ellipsis;\n}\n.profile__primary-action-button .icon[data-v-cdc2cc30] {\n  display: inline-block;\n  vertical-align: middle;\n  margin-bottom: 2px;\n  margin-right: 4px;\n}\n.profile__primary-action-button .icon.icon-invert[data-v-cdc2cc30] {\n  filter: invert(1);\n}\n.profile__primary-action-button[data-v-cdc2cc30]:hover, .profile__primary-action-button[data-v-cdc2cc30]:focus, .profile__primary-action-button[data-v-cdc2cc30]:active {\n  background-color: var(--color-primary-element-light);\n}", ""]);
// Exports
/* harmony default export */ __webpack_exports__["default"] = (___CSS_LOADER_EXPORT___);


/***/ }),

/***/ "./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=0&lang=scss&":
/*!***********************************************************************************************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=0&lang=scss& ***!
  \***********************************************************************************************************************************************************************************************************************************************************************/
/***/ (function(module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../node_modules/css-loader/dist/runtime/noSourceMaps.js */ "./node_modules/css-loader/dist/runtime/noSourceMaps.js");
/* harmony import */ var _node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../node_modules/css-loader/dist/runtime/api.js */ "./node_modules/css-loader/dist/runtime/api.js");
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__);
// Imports


var ___CSS_LOADER_EXPORT___ = _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default()((_node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default()));
// Module
___CSS_LOADER_EXPORT___.push([module.id, "#header {\n  background-color: transparent !important;\n  background-image: none !important;\n}\n#content {\n  padding-top: 0px;\n}", ""]);
// Exports
/* harmony default export */ __webpack_exports__["default"] = (___CSS_LOADER_EXPORT___);


/***/ }),

/***/ "./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true&":
/*!***********************************************************************************************************************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true& ***!
  \***********************************************************************************************************************************************************************************************************************************************************************************************/
/***/ (function(module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../../../node_modules/css-loader/dist/runtime/noSourceMaps.js */ "./node_modules/css-loader/dist/runtime/noSourceMaps.js");
/* harmony import */ var _node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../../node_modules/css-loader/dist/runtime/api.js */ "./node_modules/css-loader/dist/runtime/api.js");
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__);
// Imports


var ___CSS_LOADER_EXPORT___ = _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default()((_node_modules_css_loader_dist_runtime_noSourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default()));
// Module
___CSS_LOADER_EXPORT___.push([module.id, ".profile[data-v-8ecdffca] {\n  width: 100%;\n}\n.profile__header[data-v-8ecdffca] {\n  position: sticky;\n  height: 190px;\n  top: -40px;\n}\n.profile__header__container[data-v-8ecdffca] {\n  align-self: flex-end;\n  width: 100%;\n  max-width: 1024px;\n  margin: 0 auto;\n  display: grid;\n  grid-template-rows: max-content max-content;\n  grid-template-columns: 240px 1fr;\n  justify-content: center;\n}\n.profile__header__container__placeholder[data-v-8ecdffca] {\n  grid-row: 1/3;\n}\n.profile__header__container__displayname[data-v-8ecdffca], .profile__header__container__status-text[data-v-8ecdffca] {\n  color: var(--color-primary-text);\n}\n.profile__header__container__displayname[data-v-8ecdffca] {\n  width: 640px;\n  height: 45px;\n  margin-top: 128px;\n  margin-bottom: 0;\n  font-size: 30px;\n  display: flex;\n  align-items: center;\n  cursor: text;\n}\n.profile__header__container__displayname[data-v-8ecdffca]:not(:last-child) {\n  margin-top: 100px;\n  margin-bottom: 4px;\n}\n.profile__header__container__edit-button[data-v-8ecdffca] {\n  border: none;\n  margin-left: 18px;\n  margin-top: 2px;\n  color: var(--color-primary-element);\n  background-color: var(--color-primary-text);\n  box-shadow: 0 0 0 2px var(--color-primary-text);\n  border-radius: var(--border-radius-pill);\n  padding: 0 18px;\n  font-size: var(--default-font-size);\n  height: 44px;\n  line-height: 44px;\n  font-weight: bold;\n}\n.profile__header__container__edit-button[data-v-8ecdffca]:hover, .profile__header__container__edit-button[data-v-8ecdffca]:focus, .profile__header__container__edit-button[data-v-8ecdffca]:active {\n  color: var(--color-primary-text);\n  background-color: var(--color-primary-element-light);\n}\n.profile__header__container__edit-button .pencil-icon[data-v-8ecdffca] {\n  display: inline-block;\n  vertical-align: middle;\n  margin-top: 2px;\n}\n.profile__header__container__status-text[data-v-8ecdffca] {\n  width: max-content;\n  max-width: 640px;\n  padding: 5px 10px;\n  margin-left: -12px;\n  margin-top: 2px;\n}\n.profile__header__container__status-text.interactive[data-v-8ecdffca] {\n  cursor: pointer;\n}\n.profile__header__container__status-text.interactive[data-v-8ecdffca]:hover, .profile__header__container__status-text.interactive[data-v-8ecdffca]:focus, .profile__header__container__status-text.interactive[data-v-8ecdffca]:active {\n  background-color: var(--color-main-background);\n  color: var(--color-main-text);\n  border-radius: var(--border-radius-pill);\n  font-weight: bold;\n  box-shadow: 0 3px 6px var(--color-box-shadow);\n}\n.profile__sidebar[data-v-8ecdffca] {\n  position: sticky;\n  top: var(--header-height);\n  align-self: flex-start;\n  padding-top: 20px;\n  min-width: 220px;\n  margin: -150px 20px 0 0;\n}\n.profile__sidebar[data-v-8ecdffca] .avatar.avatardiv, .profile__sidebar h2[data-v-8ecdffca] {\n  text-align: center;\n  margin: auto;\n  display: block;\n  padding: 8px;\n}\n.profile__sidebar[data-v-8ecdffca] .avatar.avatardiv:not(.avatardiv--unknown) {\n  background-color: var(--color-main-background) !important;\n  box-shadow: none;\n}\n.profile__sidebar[data-v-8ecdffca] .avatar.avatardiv .avatardiv__user-status {\n  right: 14px;\n  bottom: 14px;\n  width: 34px;\n  height: 34px;\n  background-size: 28px;\n  border: none;\n  background-color: var(--color-main-background);\n  line-height: 34px;\n  font-size: 20px;\n}\n.profile__sidebar[data-v-8ecdffca] .avatar.interactive.avatardiv .avatardiv__user-status {\n  cursor: pointer;\n}\n.profile__sidebar[data-v-8ecdffca] .avatar.interactive.avatardiv .avatardiv__user-status:hover, .profile__sidebar[data-v-8ecdffca] .avatar.interactive.avatardiv .avatardiv__user-status:focus, .profile__sidebar[data-v-8ecdffca] .avatar.interactive.avatardiv .avatardiv__user-status:active {\n  box-shadow: 0 3px 6px var(--color-box-shadow);\n}\n.profile__content[data-v-8ecdffca] {\n  max-width: 1024px;\n  margin: 0 auto;\n  display: flex;\n  width: 100%;\n}\n.profile__blocks[data-v-8ecdffca] {\n  margin: 18px 0 80px 0;\n  display: grid;\n  gap: 16px 0;\n  width: 640px;\n}\n.profile__blocks p[data-v-8ecdffca], .profile__blocks h3[data-v-8ecdffca] {\n  overflow-wrap: anywhere;\n}\n.profile__blocks-details[data-v-8ecdffca] {\n  display: flex;\n  flex-direction: column;\n  gap: 2px 0;\n}\n.profile__blocks-details .detail[data-v-8ecdffca] {\n  display: inline-block;\n  color: var(--color-text-maxcontrast);\n}\n.profile__blocks-details .detail p .map-icon[data-v-8ecdffca] {\n  display: inline-block;\n  vertical-align: middle;\n}\n.profile__blocks-headline[data-v-8ecdffca] {\n  margin-top: 10px;\n}\n.profile__blocks-headline h3[data-v-8ecdffca] {\n  font-weight: bold;\n  font-size: 20px;\n  margin: 0;\n}\n.profile__blocks-biography[data-v-8ecdffca] {\n  white-space: pre-line;\n}\n.profile__blocks h3[data-v-8ecdffca], .profile__blocks p[data-v-8ecdffca] {\n  cursor: text;\n}\n.profile__blocks-empty-info[data-v-8ecdffca] {\n  margin-top: 80px;\n  margin-right: 100px;\n  display: flex;\n  flex-direction: column;\n  text-align: center;\n}\n.profile__blocks-empty-info h3[data-v-8ecdffca] {\n  font-weight: bold;\n  font-size: 18px;\n  margin: 8px 0;\n}\n@media only screen and (max-width: 1024px) {\n.profile__header[data-v-8ecdffca] {\n    height: 250px;\n    position: unset;\n}\n.profile__header__container[data-v-8ecdffca] {\n    grid-template-columns: unset;\n}\n.profile__header__container__displayname[data-v-8ecdffca] {\n    margin: 100px 20px 0px;\n    width: unset;\n    display: unset;\n    text-align: center;\n}\n.profile__header__container__edit-button[data-v-8ecdffca] {\n    width: fit-content;\n    display: block;\n    margin: 30px auto;\n}\n.profile__content[data-v-8ecdffca] {\n    display: block;\n}\n.profile__blocks[data-v-8ecdffca] {\n    width: unset;\n    max-width: 600px;\n    margin: 0 auto;\n    padding: 20px 50px 50px 50px;\n}\n.profile__blocks-empty-info[data-v-8ecdffca] {\n    margin: 0;\n}\n.profile__sidebar[data-v-8ecdffca] {\n    margin: unset;\n    position: unset;\n}\n}\n.user-actions[data-v-8ecdffca] {\n  display: flex;\n  flex-direction: column;\n  gap: 8px 0;\n  margin-top: 20px;\n}\n.user-actions__primary[data-v-8ecdffca] {\n  margin: 0 auto;\n}\n.user-actions__other[data-v-8ecdffca] {\n  display: flex;\n  justify-content: center;\n  gap: 0 4px;\n}\n.icon-invert[data-v-8ecdffca] .action-link__icon {\n  filter: invert(1);\n}", ""]);
// Exports
/* harmony default export */ __webpack_exports__["default"] = (___CSS_LOADER_EXPORT___);


/***/ }),

/***/ "./node_modules/style-loader/dist/cjs.js!./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true&":
/*!****************************************************************************************************************************************************************************************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/style-loader/dist/cjs.js!./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true& ***!
  \****************************************************************************************************************************************************************************************************************************************************************************************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! !../../../../node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js */ "./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! !../../../../node_modules/style-loader/dist/runtime/styleDomAPI.js */ "./node_modules/style-loader/dist/runtime/styleDomAPI.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! !../../../../node_modules/style-loader/dist/runtime/insertBySelector.js */ "./node_modules/style-loader/dist/runtime/insertBySelector.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! !../../../../node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js */ "./node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! !../../../../node_modules/style-loader/dist/runtime/insertStyleElement.js */ "./node_modules/style-loader/dist/runtime/insertStyleElement.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! !../../../../node_modules/style-loader/dist/runtime/styleTagTransform.js */ "./node_modules/style-loader/dist/runtime/styleTagTransform.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5__);
/* harmony import */ var _node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_style_index_0_id_cdc2cc30_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! !!../../../../node_modules/css-loader/dist/cjs.js!../../../../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../../../../node_modules/sass-loader/dist/cjs.js!../../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true& */ "./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true&");

      
      
      
      
      
      
      
      
      

var options = {};

options.styleTagTransform = (_node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5___default());
options.setAttributes = (_node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3___default());

      options.insert = _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2___default().bind(null, "head");
    
options.domAPI = (_node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1___default());
options.insertStyleElement = (_node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4___default());

var update = _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0___default()(_node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_style_index_0_id_cdc2cc30_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__["default"], options);




       /* harmony default export */ __webpack_exports__["default"] = (_node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_style_index_0_id_cdc2cc30_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__["default"] && _node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_style_index_0_id_cdc2cc30_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__["default"].locals ? _node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_style_index_0_id_cdc2cc30_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__["default"].locals : undefined);


/***/ }),

/***/ "./node_modules/style-loader/dist/cjs.js!./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=0&lang=scss&":
/*!***************************************************************************************************************************************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/style-loader/dist/cjs.js!./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=0&lang=scss& ***!
  \***************************************************************************************************************************************************************************************************************************************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js */ "./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/styleDomAPI.js */ "./node_modules/style-loader/dist/runtime/styleDomAPI.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/insertBySelector.js */ "./node_modules/style-loader/dist/runtime/insertBySelector.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js */ "./node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/insertStyleElement.js */ "./node_modules/style-loader/dist/runtime/insertStyleElement.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/styleTagTransform.js */ "./node_modules/style-loader/dist/runtime/styleTagTransform.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5__);
/* harmony import */ var _node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_0_lang_scss___WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! !!../../../node_modules/css-loader/dist/cjs.js!../../../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../../../node_modules/sass-loader/dist/cjs.js!../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./Profile.vue?vue&type=style&index=0&lang=scss& */ "./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=0&lang=scss&");

      
      
      
      
      
      
      
      
      

var options = {};

options.styleTagTransform = (_node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5___default());
options.setAttributes = (_node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3___default());

      options.insert = _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2___default().bind(null, "head");
    
options.domAPI = (_node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1___default());
options.insertStyleElement = (_node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4___default());

var update = _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0___default()(_node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_0_lang_scss___WEBPACK_IMPORTED_MODULE_6__["default"], options);




       /* harmony default export */ __webpack_exports__["default"] = (_node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_0_lang_scss___WEBPACK_IMPORTED_MODULE_6__["default"] && _node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_0_lang_scss___WEBPACK_IMPORTED_MODULE_6__["default"].locals ? _node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_0_lang_scss___WEBPACK_IMPORTED_MODULE_6__["default"].locals : undefined);


/***/ }),

/***/ "./node_modules/style-loader/dist/cjs.js!./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true&":
/*!***************************************************************************************************************************************************************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/style-loader/dist/cjs.js!./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true& ***!
  \***************************************************************************************************************************************************************************************************************************************************************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js */ "./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/styleDomAPI.js */ "./node_modules/style-loader/dist/runtime/styleDomAPI.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/insertBySelector.js */ "./node_modules/style-loader/dist/runtime/insertBySelector.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js */ "./node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/insertStyleElement.js */ "./node_modules/style-loader/dist/runtime/insertStyleElement.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! !../../../node_modules/style-loader/dist/runtime/styleTagTransform.js */ "./node_modules/style-loader/dist/runtime/styleTagTransform.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5__);
/* harmony import */ var _node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_1_id_8ecdffca_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! !!../../../node_modules/css-loader/dist/cjs.js!../../../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../../../node_modules/sass-loader/dist/cjs.js!../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true& */ "./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true&");

      
      
      
      
      
      
      
      
      

var options = {};

options.styleTagTransform = (_node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5___default());
options.setAttributes = (_node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3___default());

      options.insert = _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2___default().bind(null, "head");
    
options.domAPI = (_node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1___default());
options.insertStyleElement = (_node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4___default());

var update = _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0___default()(_node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_1_id_8ecdffca_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__["default"], options);




       /* harmony default export */ __webpack_exports__["default"] = (_node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_1_id_8ecdffca_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__["default"] && _node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_1_id_8ecdffca_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__["default"].locals ? _node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_1_id_8ecdffca_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_6__["default"].locals : undefined);


/***/ }),

/***/ "./core/src/components/Profile/PrimaryActionButton.vue":
/*!*************************************************************!*\
  !*** ./core/src/components/Profile/PrimaryActionButton.vue ***!
  \*************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _PrimaryActionButton_vue_vue_type_template_id_cdc2cc30_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./PrimaryActionButton.vue?vue&type=template&id=cdc2cc30&scoped=true& */ "./core/src/components/Profile/PrimaryActionButton.vue?vue&type=template&id=cdc2cc30&scoped=true&");
/* harmony import */ var _PrimaryActionButton_vue_vue_type_script_lang_js___WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./PrimaryActionButton.vue?vue&type=script&lang=js& */ "./core/src/components/Profile/PrimaryActionButton.vue?vue&type=script&lang=js&");
/* harmony import */ var _PrimaryActionButton_vue_vue_type_style_index_0_id_cdc2cc30_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true& */ "./core/src/components/Profile/PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true&");
/* harmony import */ var _node_modules_vue_loader_lib_runtime_componentNormalizer_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! !../../../../node_modules/vue-loader/lib/runtime/componentNormalizer.js */ "./node_modules/vue-loader/lib/runtime/componentNormalizer.js");



;


/* normalize component */

var component = (0,_node_modules_vue_loader_lib_runtime_componentNormalizer_js__WEBPACK_IMPORTED_MODULE_3__["default"])(
  _PrimaryActionButton_vue_vue_type_script_lang_js___WEBPACK_IMPORTED_MODULE_1__["default"],
  _PrimaryActionButton_vue_vue_type_template_id_cdc2cc30_scoped_true___WEBPACK_IMPORTED_MODULE_0__.render,
  _PrimaryActionButton_vue_vue_type_template_id_cdc2cc30_scoped_true___WEBPACK_IMPORTED_MODULE_0__.staticRenderFns,
  false,
  null,
  "cdc2cc30",
  null
  
)

/* hot reload */
if (false) { var api; }
component.options.__file = "core/src/components/Profile/PrimaryActionButton.vue"
/* harmony default export */ __webpack_exports__["default"] = (component.exports);

/***/ }),

/***/ "./core/src/views/Profile.vue":
/*!************************************!*\
  !*** ./core/src/views/Profile.vue ***!
  \************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _Profile_vue_vue_type_template_id_8ecdffca_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./Profile.vue?vue&type=template&id=8ecdffca&scoped=true& */ "./core/src/views/Profile.vue?vue&type=template&id=8ecdffca&scoped=true&");
/* harmony import */ var _Profile_vue_vue_type_script_lang_js___WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./Profile.vue?vue&type=script&lang=js& */ "./core/src/views/Profile.vue?vue&type=script&lang=js&");
/* harmony import */ var _Profile_vue_vue_type_style_index_0_lang_scss___WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./Profile.vue?vue&type=style&index=0&lang=scss& */ "./core/src/views/Profile.vue?vue&type=style&index=0&lang=scss&");
/* harmony import */ var _Profile_vue_vue_type_style_index_1_id_8ecdffca_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true& */ "./core/src/views/Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true&");
/* harmony import */ var _node_modules_vue_loader_lib_runtime_componentNormalizer_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! !../../../node_modules/vue-loader/lib/runtime/componentNormalizer.js */ "./node_modules/vue-loader/lib/runtime/componentNormalizer.js");



;



/* normalize component */

var component = (0,_node_modules_vue_loader_lib_runtime_componentNormalizer_js__WEBPACK_IMPORTED_MODULE_4__["default"])(
  _Profile_vue_vue_type_script_lang_js___WEBPACK_IMPORTED_MODULE_1__["default"],
  _Profile_vue_vue_type_template_id_8ecdffca_scoped_true___WEBPACK_IMPORTED_MODULE_0__.render,
  _Profile_vue_vue_type_template_id_8ecdffca_scoped_true___WEBPACK_IMPORTED_MODULE_0__.staticRenderFns,
  false,
  null,
  "8ecdffca",
  null
  
)

/* hot reload */
if (false) { var api; }
component.options.__file = "core/src/views/Profile.vue"
/* harmony default export */ __webpack_exports__["default"] = (component.exports);

/***/ }),

/***/ "./core/src/components/Profile/PrimaryActionButton.vue?vue&type=script&lang=js&":
/*!**************************************************************************************!*\
  !*** ./core/src/components/Profile/PrimaryActionButton.vue?vue&type=script&lang=js& ***!
  \**************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_babel_loader_lib_index_js_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_script_lang_js___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! -!../../../../node_modules/babel-loader/lib/index.js!../../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./PrimaryActionButton.vue?vue&type=script&lang=js& */ "./node_modules/babel-loader/lib/index.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=script&lang=js&");
 /* harmony default export */ __webpack_exports__["default"] = (_node_modules_babel_loader_lib_index_js_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_script_lang_js___WEBPACK_IMPORTED_MODULE_0__["default"]); 

/***/ }),

/***/ "./core/src/views/Profile.vue?vue&type=script&lang=js&":
/*!*************************************************************!*\
  !*** ./core/src/views/Profile.vue?vue&type=script&lang=js& ***!
  \*************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_babel_loader_lib_index_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_script_lang_js___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! -!../../../node_modules/babel-loader/lib/index.js!../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./Profile.vue?vue&type=script&lang=js& */ "./node_modules/babel-loader/lib/index.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=script&lang=js&");
 /* harmony default export */ __webpack_exports__["default"] = (_node_modules_babel_loader_lib_index_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_script_lang_js___WEBPACK_IMPORTED_MODULE_0__["default"]); 

/***/ }),

/***/ "./core/src/components/Profile/PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true&":
/*!***********************************************************************************************************************!*\
  !*** ./core/src/components/Profile/PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true& ***!
  \***********************************************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_style_loader_dist_cjs_js_node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_style_index_0_id_cdc2cc30_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! -!../../../../node_modules/style-loader/dist/cjs.js!../../../../node_modules/css-loader/dist/cjs.js!../../../../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../../../../node_modules/sass-loader/dist/cjs.js!../../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true& */ "./node_modules/style-loader/dist/cjs.js!./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=style&index=0&id=cdc2cc30&lang=scss&scoped=true&");


/***/ }),

/***/ "./core/src/views/Profile.vue?vue&type=style&index=0&lang=scss&":
/*!**********************************************************************!*\
  !*** ./core/src/views/Profile.vue?vue&type=style&index=0&lang=scss& ***!
  \**********************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_style_loader_dist_cjs_js_node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_0_lang_scss___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! -!../../../node_modules/style-loader/dist/cjs.js!../../../node_modules/css-loader/dist/cjs.js!../../../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../../../node_modules/sass-loader/dist/cjs.js!../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./Profile.vue?vue&type=style&index=0&lang=scss& */ "./node_modules/style-loader/dist/cjs.js!./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=0&lang=scss&");


/***/ }),

/***/ "./core/src/views/Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true&":
/*!**********************************************************************************************!*\
  !*** ./core/src/views/Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true& ***!
  \**********************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _node_modules_style_loader_dist_cjs_js_node_modules_css_loader_dist_cjs_js_node_modules_vue_loader_lib_loaders_stylePostLoader_js_node_modules_sass_loader_dist_cjs_js_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_style_index_1_id_8ecdffca_lang_scss_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! -!../../../node_modules/style-loader/dist/cjs.js!../../../node_modules/css-loader/dist/cjs.js!../../../node_modules/vue-loader/lib/loaders/stylePostLoader.js!../../../node_modules/sass-loader/dist/cjs.js!../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true& */ "./node_modules/style-loader/dist/cjs.js!./node_modules/css-loader/dist/cjs.js!./node_modules/vue-loader/lib/loaders/stylePostLoader.js!./node_modules/sass-loader/dist/cjs.js!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=style&index=1&id=8ecdffca&lang=scss&scoped=true&");


/***/ }),

/***/ "./core/src/components/Profile/PrimaryActionButton.vue?vue&type=template&id=cdc2cc30&scoped=true&":
/*!********************************************************************************************************!*\
  !*** ./core/src/components/Profile/PrimaryActionButton.vue?vue&type=template&id=cdc2cc30&scoped=true& ***!
  \********************************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "render": function() { return /* reexport safe */ _node_modules_vue_loader_lib_loaders_templateLoader_js_vue_loader_options_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_template_id_cdc2cc30_scoped_true___WEBPACK_IMPORTED_MODULE_0__.render; },
/* harmony export */   "staticRenderFns": function() { return /* reexport safe */ _node_modules_vue_loader_lib_loaders_templateLoader_js_vue_loader_options_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_template_id_cdc2cc30_scoped_true___WEBPACK_IMPORTED_MODULE_0__.staticRenderFns; }
/* harmony export */ });
/* harmony import */ var _node_modules_vue_loader_lib_loaders_templateLoader_js_vue_loader_options_node_modules_vue_loader_lib_index_js_vue_loader_options_PrimaryActionButton_vue_vue_type_template_id_cdc2cc30_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! -!../../../../node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!../../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./PrimaryActionButton.vue?vue&type=template&id=cdc2cc30&scoped=true& */ "./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=template&id=cdc2cc30&scoped=true&");


/***/ }),

/***/ "./core/src/views/Profile.vue?vue&type=template&id=8ecdffca&scoped=true&":
/*!*******************************************************************************!*\
  !*** ./core/src/views/Profile.vue?vue&type=template&id=8ecdffca&scoped=true& ***!
  \*******************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "render": function() { return /* reexport safe */ _node_modules_vue_loader_lib_loaders_templateLoader_js_vue_loader_options_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_template_id_8ecdffca_scoped_true___WEBPACK_IMPORTED_MODULE_0__.render; },
/* harmony export */   "staticRenderFns": function() { return /* reexport safe */ _node_modules_vue_loader_lib_loaders_templateLoader_js_vue_loader_options_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_template_id_8ecdffca_scoped_true___WEBPACK_IMPORTED_MODULE_0__.staticRenderFns; }
/* harmony export */ });
/* harmony import */ var _node_modules_vue_loader_lib_loaders_templateLoader_js_vue_loader_options_node_modules_vue_loader_lib_index_js_vue_loader_options_Profile_vue_vue_type_template_id_8ecdffca_scoped_true___WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! -!../../../node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!../../../node_modules/vue-loader/lib/index.js??vue-loader-options!./Profile.vue?vue&type=template&id=8ecdffca&scoped=true& */ "./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=template&id=8ecdffca&scoped=true&");


/***/ }),

/***/ "./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=template&id=cdc2cc30&scoped=true&":
/*!***********************************************************************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/components/Profile/PrimaryActionButton.vue?vue&type=template&id=cdc2cc30&scoped=true& ***!
  \***********************************************************************************************************************************************************************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "render": function() { return /* binding */ render; },
/* harmony export */   "staticRenderFns": function() { return /* binding */ staticRenderFns; }
/* harmony export */ });
var render = function () {
  var _vm = this
  var _h = _vm.$createElement
  var _c = _vm._self._c || _h
  return _c(
    "a",
    _vm._g(
      {
        staticClass: "profile__primary-action-button",
        class: { disabled: _vm.disabled },
        attrs: {
          href: _vm.href,
          target: _vm.target,
          rel: "noopener noreferrer nofollow",
        },
      },
      _vm.$listeners
    ),
    [
      _c("img", {
        staticClass: "icon",
        class: [
          _vm.icon,
          { "icon-invert": _vm.colorPrimaryText === "#ffffff" },
        ],
        attrs: { src: _vm.icon },
      }),
      _vm._v(" "),
      _vm._t("default"),
    ],
    2
  )
}
var staticRenderFns = []
render._withStripped = true



/***/ }),

/***/ "./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=template&id=8ecdffca&scoped=true&":
/*!**********************************************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/vue-loader/lib/loaders/templateLoader.js??vue-loader-options!./node_modules/vue-loader/lib/index.js??vue-loader-options!./core/src/views/Profile.vue?vue&type=template&id=8ecdffca&scoped=true& ***!
  \**********************************************************************************************************************************************************************************************************************/
/***/ (function(__unused_webpack_module, __webpack_exports__, __webpack_require__) {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "render": function() { return /* binding */ render; },
/* harmony export */   "staticRenderFns": function() { return /* binding */ staticRenderFns; }
/* harmony export */ });
var render = function () {
  var _vm = this
  var _h = _vm.$createElement
  var _c = _vm._self._c || _h
  return _c("div", { staticClass: "profile" }, [
    _c("div", { staticClass: "profile__header" }, [
      _c("div", { staticClass: "profile__header__container" }, [
        _c("div", { staticClass: "profile__header__container__placeholder" }),
        _vm._v(" "),
        _c("h2", { staticClass: "profile__header__container__displayname" }, [
          _vm._v(
            "\n\t\t\t\t" + _vm._s(_vm.displayname || _vm.userId) + "\n\t\t\t\t"
          ),
          _vm.isCurrentUser
            ? _c(
                "a",
                {
                  staticClass:
                    "primary profile__header__container__edit-button",
                  attrs: { href: _vm.settingsUrl },
                },
                [
                  _c("PencilIcon", {
                    staticClass: "pencil-icon",
                    attrs: { decorative: "", title: "", size: 16 },
                  }),
                  _vm._v(
                    "\n\t\t\t\t\t" +
                      _vm._s(_vm.t("core", "Edit Profile")) +
                      "\n\t\t\t\t"
                  ),
                ],
                1
              )
            : _vm._e(),
        ]),
        _vm._v(" "),
        _vm.status.icon || _vm.status.message
          ? _c(
              "div",
              {
                staticClass: "profile__header__container__status-text",
                class: { interactive: _vm.isCurrentUser },
                on: {
                  click: function ($event) {
                    $event.preventDefault()
                    $event.stopPropagation()
                    return _vm.openStatusModal.apply(null, arguments)
                  },
                },
              },
              [
                _vm._v(
                  "\n\t\t\t\t" +
                    _vm._s(_vm.status.icon) +
                    " " +
                    _vm._s(_vm.status.message) +
                    "\n\t\t\t"
                ),
              ]
            )
          : _vm._e(),
      ]),
    ]),
    _vm._v(" "),
    _c("div", { staticClass: "profile__content" }, [
      _c(
        "div",
        { staticClass: "profile__sidebar" },
        [
          _c("Avatar", {
            staticClass: "avatar",
            class: { interactive: _vm.isCurrentUser },
            attrs: {
              user: _vm.userId,
              size: 180,
              "show-user-status": true,
              "show-user-status-compact": false,
              "disable-menu": true,
              "disable-tooltip": true,
              "is-no-user": !_vm.isUserAvatarVisible,
            },
            nativeOn: {
              click: function ($event) {
                $event.preventDefault()
                $event.stopPropagation()
                return _vm.openStatusModal.apply(null, arguments)
              },
            },
          }),
          _vm._v(" "),
          _c(
            "div",
            { staticClass: "user-actions" },
            [
              _vm.primaryAction
                ? _c(
                    "PrimaryActionButton",
                    {
                      staticClass: "user-actions__primary",
                      attrs: {
                        href: _vm.primaryAction.target,
                        icon: _vm.primaryAction.icon,
                        target:
                          _vm.primaryAction.id === "phone" ? "_self" : "_blank",
                      },
                    },
                    [
                      _vm._v(
                        "\n\t\t\t\t\t" +
                          _vm._s(_vm.primaryAction.title) +
                          "\n\t\t\t\t"
                      ),
                    ]
                  )
                : _vm._e(),
              _vm._v(" "),
              _c(
                "div",
                { staticClass: "user-actions__other" },
                [
                  _vm._l(_vm.middleActions, function (action) {
                    return _c(
                      "Actions",
                      {
                        key: action.id,
                        staticStyle: {
                          "background-position": "14px center",
                          "background-size": "16px",
                          "background-repeat": "no-repeat",
                        },
                        style: Object.assign(
                          {},
                          { backgroundImage: "url(" + action.icon + ")" },
                          _vm.colorMainBackground === "#181818" && {
                            filter: "invert(1)",
                          }
                        ),
                        attrs: { "default-icon": action.icon },
                      },
                      [
                        _c(
                          "ActionLink",
                          {
                            attrs: {
                              "close-after-click": true,
                              icon: action.icon,
                              href: action.target,
                              target:
                                action.id === "phone" ? "_self" : "_blank",
                            },
                          },
                          [
                            _vm._v(
                              "\n\t\t\t\t\t\t\t" +
                                _vm._s(action.title) +
                                "\n\t\t\t\t\t\t"
                            ),
                          ]
                        ),
                      ],
                      1
                    )
                  }),
                  _vm._v(" "),
                  _vm.otherActions
                    ? [
                        _c(
                          "Actions",
                          { attrs: { "force-menu": true } },
                          _vm._l(_vm.otherActions, function (action) {
                            return _c(
                              "ActionLink",
                              {
                                key: action.id,
                                class: {
                                  "icon-invert":
                                    _vm.colorMainBackground === "#181818",
                                },
                                attrs: {
                                  "close-after-click": true,
                                  icon: action.icon,
                                  href: action.target,
                                  target:
                                    action.id === "phone" ? "_self" : "_blank",
                                },
                              },
                              [
                                _vm._v(
                                  "\n\t\t\t\t\t\t\t\t" +
                                    _vm._s(action.title) +
                                    "\n\t\t\t\t\t\t\t"
                                ),
                              ]
                            )
                          }),
                          1
                        ),
                      ]
                    : _vm._e(),
                ],
                2
              ),
            ],
            1
          ),
        ],
        1
      ),
      _vm._v(" "),
      _c(
        "div",
        { staticClass: "profile__blocks" },
        [
          _vm.organisation || _vm.role || _vm.address
            ? _c("div", { staticClass: "profile__blocks-details" }, [
                _vm.organisation || _vm.role
                  ? _c("div", { staticClass: "detail" }, [
                      _c("p", [
                        _vm._v(_vm._s(_vm.organisation) + " "),
                        _vm.organisation && _vm.role
                          ? _c("span", [_vm._v("•")])
                          : _vm._e(),
                        _vm._v(" " + _vm._s(_vm.role)),
                      ]),
                    ])
                  : _vm._e(),
                _vm._v(" "),
                _vm.address
                  ? _c("div", { staticClass: "detail" }, [
                      _c(
                        "p",
                        [
                          _c("MapMarkerIcon", {
                            staticClass: "map-icon",
                            attrs: { decorative: "", title: "", size: 16 },
                          }),
                          _vm._v(
                            "\n\t\t\t\t\t\t" +
                              _vm._s(_vm.address) +
                              "\n\t\t\t\t\t"
                          ),
                        ],
                        1
                      ),
                    ])
                  : _vm._e(),
              ])
            : _vm._e(),
          _vm._v(" "),
          _vm.headline || _vm.biography
            ? [
                _vm.headline
                  ? _c("div", { staticClass: "profile__blocks-headline" }, [
                      _c("h3", [_vm._v(_vm._s(_vm.headline))]),
                    ])
                  : _vm._e(),
                _vm._v(" "),
                _vm.biography
                  ? _c("div", { staticClass: "profile__blocks-biography" }, [
                      _c("p", [_vm._v(_vm._s(_vm.biography))]),
                    ])
                  : _vm._e(),
              ]
            : [
                _c(
                  "div",
                  { staticClass: "profile__blocks-empty-info" },
                  [
                    _c("AccountIcon", {
                      attrs: {
                        decorative: "",
                        title: "",
                        "fill-color": "var(--color-text-maxcontrast)",
                        size: 60,
                      },
                    }),
                    _vm._v(" "),
                    _c("h3", [_vm._v(_vm._s(_vm.emptyProfileMessage))]),
                    _vm._v(" "),
                    _c("p", [
                      _vm._v(
                        _vm._s(
                          _vm.t(
                            "core",
                            "The headline and about sections will show up here"
                          )
                        )
                      ),
                    ]),
                  ],
                  1
                ),
              ],
        ],
        2
      ),
    ]),
  ])
}
var staticRenderFns = []
render._withStripped = true



/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			id: moduleId,
/******/ 			loaded: false,
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = __webpack_modules__;
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/amd define */
/******/ 	!function() {
/******/ 		__webpack_require__.amdD = function () {
/******/ 			throw new Error('define cannot be used indirect');
/******/ 		};
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/amd options */
/******/ 	!function() {
/******/ 		__webpack_require__.amdO = {};
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/chunk loaded */
/******/ 	!function() {
/******/ 		var deferred = [];
/******/ 		__webpack_require__.O = function(result, chunkIds, fn, priority) {
/******/ 			if(chunkIds) {
/******/ 				priority = priority || 0;
/******/ 				for(var i = deferred.length; i > 0 && deferred[i - 1][2] > priority; i--) deferred[i] = deferred[i - 1];
/******/ 				deferred[i] = [chunkIds, fn, priority];
/******/ 				return;
/******/ 			}
/******/ 			var notFulfilled = Infinity;
/******/ 			for (var i = 0; i < deferred.length; i++) {
/******/ 				var chunkIds = deferred[i][0];
/******/ 				var fn = deferred[i][1];
/******/ 				var priority = deferred[i][2];
/******/ 				var fulfilled = true;
/******/ 				for (var j = 0; j < chunkIds.length; j++) {
/******/ 					if ((priority & 1 === 0 || notFulfilled >= priority) && Object.keys(__webpack_require__.O).every(function(key) { return __webpack_require__.O[key](chunkIds[j]); })) {
/******/ 						chunkIds.splice(j--, 1);
/******/ 					} else {
/******/ 						fulfilled = false;
/******/ 						if(priority < notFulfilled) notFulfilled = priority;
/******/ 					}
/******/ 				}
/******/ 				if(fulfilled) {
/******/ 					deferred.splice(i--, 1)
/******/ 					var r = fn();
/******/ 					if (r !== undefined) result = r;
/******/ 				}
/******/ 			}
/******/ 			return result;
/******/ 		};
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	!function() {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = function(module) {
/******/ 			var getter = module && module.__esModule ?
/******/ 				function() { return module['default']; } :
/******/ 				function() { return module; };
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	!function() {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = function(exports, definition) {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/global */
/******/ 	!function() {
/******/ 		__webpack_require__.g = (function() {
/******/ 			if (typeof globalThis === 'object') return globalThis;
/******/ 			try {
/******/ 				return this || new Function('return this')();
/******/ 			} catch (e) {
/******/ 				if (typeof window === 'object') return window;
/******/ 			}
/******/ 		})();
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	!function() {
/******/ 		__webpack_require__.o = function(obj, prop) { return Object.prototype.hasOwnProperty.call(obj, prop); }
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	!function() {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = function(exports) {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/node module decorator */
/******/ 	!function() {
/******/ 		__webpack_require__.nmd = function(module) {
/******/ 			module.paths = [];
/******/ 			if (!module.children) module.children = [];
/******/ 			return module;
/******/ 		};
/******/ 	}();
/******/ 	
/******/ 	/* webpack/runtime/jsonp chunk loading */
/******/ 	!function() {
/******/ 		__webpack_require__.b = document.baseURI || self.location.href;
/******/ 		
/******/ 		// object to store loaded and loading chunks
/******/ 		// undefined = chunk not loaded, null = chunk preloaded/prefetched
/******/ 		// [resolve, reject, Promise] = chunk loading, 0 = chunk loaded
/******/ 		var installedChunks = {
/******/ 			"core-profile": 0
/******/ 		};
/******/ 		
/******/ 		// no chunk on demand loading
/******/ 		
/******/ 		// no prefetching
/******/ 		
/******/ 		// no preloaded
/******/ 		
/******/ 		// no HMR
/******/ 		
/******/ 		// no HMR manifest
/******/ 		
/******/ 		__webpack_require__.O.j = function(chunkId) { return installedChunks[chunkId] === 0; };
/******/ 		
/******/ 		// install a JSONP callback for chunk loading
/******/ 		var webpackJsonpCallback = function(parentChunkLoadingFunction, data) {
/******/ 			var chunkIds = data[0];
/******/ 			var moreModules = data[1];
/******/ 			var runtime = data[2];
/******/ 			// add "moreModules" to the modules object,
/******/ 			// then flag all "chunkIds" as loaded and fire callback
/******/ 			var moduleId, chunkId, i = 0;
/******/ 			if(chunkIds.some(function(id) { return installedChunks[id] !== 0; })) {
/******/ 				for(moduleId in moreModules) {
/******/ 					if(__webpack_require__.o(moreModules, moduleId)) {
/******/ 						__webpack_require__.m[moduleId] = moreModules[moduleId];
/******/ 					}
/******/ 				}
/******/ 				if(runtime) var result = runtime(__webpack_require__);
/******/ 			}
/******/ 			if(parentChunkLoadingFunction) parentChunkLoadingFunction(data);
/******/ 			for(;i < chunkIds.length; i++) {
/******/ 				chunkId = chunkIds[i];
/******/ 				if(__webpack_require__.o(installedChunks, chunkId) && installedChunks[chunkId]) {
/******/ 					installedChunks[chunkId][0]();
/******/ 				}
/******/ 				installedChunks[chunkId] = 0;
/******/ 			}
/******/ 			return __webpack_require__.O(result);
/******/ 		}
/******/ 		
/******/ 		var chunkLoadingGlobal = self["webpackChunknextcloud"] = self["webpackChunknextcloud"] || [];
/******/ 		chunkLoadingGlobal.forEach(webpackJsonpCallback.bind(null, 0));
/******/ 		chunkLoadingGlobal.push = webpackJsonpCallback.bind(null, chunkLoadingGlobal.push.bind(chunkLoadingGlobal));
/******/ 	}();
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module depends on other loaded chunks and execution need to be delayed
/******/ 	var __webpack_exports__ = __webpack_require__.O(undefined, ["core-common"], function() { return __webpack_require__("./core/src/profile.js"); })
/******/ 	__webpack_exports__ = __webpack_require__.O(__webpack_exports__);
/******/ 	
/******/ })()
;
//# sourceMappingURL=core-profile.js.map?v=4cb0d7fa749e65f10551