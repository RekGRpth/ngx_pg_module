
#line 1 "pg_fsm.rl"
#include "pg_fsm.h"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

typedef struct pg_fsm_t {
    const uint8_t *string;
    uint16_t cs;
    uint16_t data_row_count;
    uint16_t int2;
    uint16_t row_description_count;
    uint32_t int4;
    uint32_t result_len;
    uint8_t i;
} pg_fsm_t;


#line 19 "pg_fsm.c"
static const int pg_fsm_start = 397;


#line 192 "pg_fsm.rl"


size_t pg_fsm_execute(pg_fsm_t *m, const pg_fsm_cb_t *f, const void *u, const uint8_t *p, const uint8_t *pe) {
    const uint8_t *b = p;
    const uint8_t *eof = pe;
    
#line 30 "pg_fsm.c"
	{
	if ( p == pe )
		goto _test_eof;
	goto _resume;

_again:
	switch (  m->cs ) {
		case 397: goto st397;
		case 0: goto st0;
		case 1: goto st1;
		case 2: goto st2;
		case 3: goto st3;
		case 4: goto st4;
		case 5: goto st5;
		case 6: goto st6;
		case 7: goto st7;
		case 8: goto st8;
		case 9: goto st9;
		case 10: goto st10;
		case 11: goto st11;
		case 12: goto st12;
		case 13: goto st13;
		case 14: goto st14;
		case 15: goto st15;
		case 16: goto st16;
		case 17: goto st17;
		case 18: goto st18;
		case 19: goto st19;
		case 20: goto st20;
		case 21: goto st21;
		case 22: goto st22;
		case 23: goto st23;
		case 24: goto st24;
		case 25: goto st25;
		case 26: goto st26;
		case 27: goto st27;
		case 28: goto st28;
		case 29: goto st29;
		case 30: goto st30;
		case 31: goto st31;
		case 32: goto st32;
		case 33: goto st33;
		case 34: goto st34;
		case 35: goto st35;
		case 36: goto st36;
		case 37: goto st37;
		case 38: goto st38;
		case 39: goto st39;
		case 40: goto st40;
		case 398: goto st398;
		case 41: goto st41;
		case 42: goto st42;
		case 43: goto st43;
		case 44: goto st44;
		case 45: goto st45;
		case 46: goto st46;
		case 47: goto st47;
		case 48: goto st48;
		case 49: goto st49;
		case 50: goto st50;
		case 51: goto st51;
		case 52: goto st52;
		case 53: goto st53;
		case 54: goto st54;
		case 55: goto st55;
		case 56: goto st56;
		case 57: goto st57;
		case 58: goto st58;
		case 59: goto st59;
		case 60: goto st60;
		case 61: goto st61;
		case 62: goto st62;
		case 63: goto st63;
		case 64: goto st64;
		case 65: goto st65;
		case 66: goto st66;
		case 67: goto st67;
		case 68: goto st68;
		case 69: goto st69;
		case 70: goto st70;
		case 71: goto st71;
		case 72: goto st72;
		case 73: goto st73;
		case 74: goto st74;
		case 75: goto st75;
		case 76: goto st76;
		case 77: goto st77;
		case 78: goto st78;
		case 79: goto st79;
		case 80: goto st80;
		case 81: goto st81;
		case 82: goto st82;
		case 83: goto st83;
		case 84: goto st84;
		case 85: goto st85;
		case 86: goto st86;
		case 87: goto st87;
		case 88: goto st88;
		case 89: goto st89;
		case 399: goto st399;
		case 90: goto st90;
		case 91: goto st91;
		case 92: goto st92;
		case 93: goto st93;
		case 94: goto st94;
		case 95: goto st95;
		case 96: goto st96;
		case 97: goto st97;
		case 98: goto st98;
		case 99: goto st99;
		case 100: goto st100;
		case 101: goto st101;
		case 102: goto st102;
		case 103: goto st103;
		case 104: goto st104;
		case 105: goto st105;
		case 106: goto st106;
		case 107: goto st107;
		case 108: goto st108;
		case 109: goto st109;
		case 110: goto st110;
		case 111: goto st111;
		case 112: goto st112;
		case 113: goto st113;
		case 114: goto st114;
		case 115: goto st115;
		case 116: goto st116;
		case 117: goto st117;
		case 118: goto st118;
		case 119: goto st119;
		case 120: goto st120;
		case 121: goto st121;
		case 122: goto st122;
		case 123: goto st123;
		case 124: goto st124;
		case 125: goto st125;
		case 126: goto st126;
		case 400: goto st400;
		case 127: goto st127;
		case 128: goto st128;
		case 129: goto st129;
		case 130: goto st130;
		case 131: goto st131;
		case 132: goto st132;
		case 133: goto st133;
		case 134: goto st134;
		case 135: goto st135;
		case 136: goto st136;
		case 137: goto st137;
		case 138: goto st138;
		case 139: goto st139;
		case 140: goto st140;
		case 141: goto st141;
		case 142: goto st142;
		case 143: goto st143;
		case 144: goto st144;
		case 145: goto st145;
		case 146: goto st146;
		case 147: goto st147;
		case 148: goto st148;
		case 149: goto st149;
		case 150: goto st150;
		case 151: goto st151;
		case 152: goto st152;
		case 153: goto st153;
		case 154: goto st154;
		case 155: goto st155;
		case 156: goto st156;
		case 157: goto st157;
		case 158: goto st158;
		case 159: goto st159;
		case 160: goto st160;
		case 161: goto st161;
		case 162: goto st162;
		case 163: goto st163;
		case 164: goto st164;
		case 165: goto st165;
		case 166: goto st166;
		case 167: goto st167;
		case 168: goto st168;
		case 169: goto st169;
		case 170: goto st170;
		case 171: goto st171;
		case 172: goto st172;
		case 173: goto st173;
		case 174: goto st174;
		case 175: goto st175;
		case 176: goto st176;
		case 177: goto st177;
		case 178: goto st178;
		case 179: goto st179;
		case 180: goto st180;
		case 181: goto st181;
		case 182: goto st182;
		case 183: goto st183;
		case 184: goto st184;
		case 185: goto st185;
		case 186: goto st186;
		case 187: goto st187;
		case 188: goto st188;
		case 189: goto st189;
		case 190: goto st190;
		case 191: goto st191;
		case 192: goto st192;
		case 193: goto st193;
		case 194: goto st194;
		case 195: goto st195;
		case 196: goto st196;
		case 197: goto st197;
		case 198: goto st198;
		case 199: goto st199;
		case 200: goto st200;
		case 201: goto st201;
		case 202: goto st202;
		case 203: goto st203;
		case 204: goto st204;
		case 205: goto st205;
		case 206: goto st206;
		case 207: goto st207;
		case 208: goto st208;
		case 209: goto st209;
		case 210: goto st210;
		case 211: goto st211;
		case 212: goto st212;
		case 213: goto st213;
		case 214: goto st214;
		case 215: goto st215;
		case 216: goto st216;
		case 217: goto st217;
		case 218: goto st218;
		case 219: goto st219;
		case 220: goto st220;
		case 221: goto st221;
		case 222: goto st222;
		case 223: goto st223;
		case 224: goto st224;
		case 225: goto st225;
		case 226: goto st226;
		case 227: goto st227;
		case 228: goto st228;
		case 229: goto st229;
		case 230: goto st230;
		case 231: goto st231;
		case 232: goto st232;
		case 233: goto st233;
		case 234: goto st234;
		case 235: goto st235;
		case 236: goto st236;
		case 237: goto st237;
		case 238: goto st238;
		case 239: goto st239;
		case 240: goto st240;
		case 241: goto st241;
		case 242: goto st242;
		case 243: goto st243;
		case 244: goto st244;
		case 245: goto st245;
		case 246: goto st246;
		case 247: goto st247;
		case 248: goto st248;
		case 249: goto st249;
		case 250: goto st250;
		case 251: goto st251;
		case 252: goto st252;
		case 253: goto st253;
		case 254: goto st254;
		case 255: goto st255;
		case 256: goto st256;
		case 257: goto st257;
		case 258: goto st258;
		case 259: goto st259;
		case 260: goto st260;
		case 261: goto st261;
		case 262: goto st262;
		case 263: goto st263;
		case 264: goto st264;
		case 265: goto st265;
		case 266: goto st266;
		case 267: goto st267;
		case 268: goto st268;
		case 269: goto st269;
		case 270: goto st270;
		case 271: goto st271;
		case 272: goto st272;
		case 273: goto st273;
		case 274: goto st274;
		case 275: goto st275;
		case 276: goto st276;
		case 277: goto st277;
		case 278: goto st278;
		case 279: goto st279;
		case 280: goto st280;
		case 281: goto st281;
		case 282: goto st282;
		case 283: goto st283;
		case 284: goto st284;
		case 285: goto st285;
		case 286: goto st286;
		case 287: goto st287;
		case 288: goto st288;
		case 289: goto st289;
		case 290: goto st290;
		case 291: goto st291;
		case 292: goto st292;
		case 293: goto st293;
		case 294: goto st294;
		case 295: goto st295;
		case 296: goto st296;
		case 297: goto st297;
		case 298: goto st298;
		case 299: goto st299;
		case 300: goto st300;
		case 301: goto st301;
		case 302: goto st302;
		case 303: goto st303;
		case 304: goto st304;
		case 305: goto st305;
		case 306: goto st306;
		case 307: goto st307;
		case 308: goto st308;
		case 309: goto st309;
		case 310: goto st310;
		case 311: goto st311;
		case 312: goto st312;
		case 313: goto st313;
		case 314: goto st314;
		case 315: goto st315;
		case 316: goto st316;
		case 317: goto st317;
		case 318: goto st318;
		case 319: goto st319;
		case 320: goto st320;
		case 321: goto st321;
		case 322: goto st322;
		case 323: goto st323;
		case 324: goto st324;
		case 325: goto st325;
		case 326: goto st326;
		case 327: goto st327;
		case 328: goto st328;
		case 329: goto st329;
		case 330: goto st330;
		case 331: goto st331;
		case 332: goto st332;
		case 333: goto st333;
		case 334: goto st334;
		case 335: goto st335;
		case 336: goto st336;
		case 337: goto st337;
		case 338: goto st338;
		case 339: goto st339;
		case 340: goto st340;
		case 341: goto st341;
		case 342: goto st342;
		case 343: goto st343;
		case 344: goto st344;
		case 345: goto st345;
		case 346: goto st346;
		case 347: goto st347;
		case 348: goto st348;
		case 349: goto st349;
		case 350: goto st350;
		case 351: goto st351;
		case 352: goto st352;
		case 353: goto st353;
		case 354: goto st354;
		case 355: goto st355;
		case 356: goto st356;
		case 357: goto st357;
		case 358: goto st358;
		case 359: goto st359;
		case 360: goto st360;
		case 361: goto st361;
		case 362: goto st362;
		case 363: goto st363;
		case 364: goto st364;
		case 365: goto st365;
		case 366: goto st366;
		case 367: goto st367;
		case 368: goto st368;
		case 369: goto st369;
		case 370: goto st370;
		case 371: goto st371;
		case 372: goto st372;
		case 373: goto st373;
		case 374: goto st374;
		case 375: goto st375;
		case 376: goto st376;
		case 377: goto st377;
		case 378: goto st378;
		case 379: goto st379;
		case 380: goto st380;
		case 381: goto st381;
		case 382: goto st382;
		case 383: goto st383;
		case 384: goto st384;
		case 385: goto st385;
		case 386: goto st386;
		case 387: goto st387;
		case 388: goto st388;
		case 389: goto st389;
		case 390: goto st390;
		case 391: goto st391;
		case 392: goto st392;
		case 393: goto st393;
		case 394: goto st394;
		case 395: goto st395;
		case 396: goto st396;
	default: break;
	}

	if ( ++p == pe )
		goto _test_eof;
_resume:
	switch (  m->cs )
	{
tr4:
#line 79 "pg_fsm.rl"
	{ if (f->parse_complete(u)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr8:
#line 27 "pg_fsm.rl"
	{ if (f->bind_complete(u)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr12:
#line 28 "pg_fsm.rl"
	{ if (f->close_complete(u)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr24:
#line 61 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->notification_response_extra(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; if (p != eof) if (f->notification_response_done(u)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr30:
#line 30 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->command_complete_val(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr110:
#line 36 "pg_fsm.rl"
	{ if (f->empty_query_response(u)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr122:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 25 "pg_fsm.rl"
	{ if (f->backend_key_data_key(u, m->int4)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr135:
#line 23 "pg_fsm.rl"
	{ if (f->authentication_ok(u)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr136:
#line 21 "pg_fsm.rl"
	{ if (f->authentication_cleartext_password(u)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr172:
#line 65 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_application_name(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr189:
#line 66 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_client_encoding(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr201:
#line 67 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_datestyle(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr231:
#line 68 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_default_transaction_read_only(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr253:
#line 71 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_integer_datetimes(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr264:
#line 72 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_intervalstyle(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr278:
#line 70 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_in_hot_standby(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr291:
#line 73 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_is_superuser(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr311:
#line 74 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_server_encoding(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr320:
#line 75 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_server_version(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr341:
#line 76 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_session_authorization(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr369:
#line 77 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_standard_conforming_strings(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr379:
#line 78 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_timezone(u, p - m->string, m->string)) {p++;  m->cs = 397; goto _out;} m->string = NULL; }
	goto st397;
tr406:
	 m->cs = 397;
#line 89 "pg_fsm.rl"
	{ if (f->row_description_format(u, 0)) {p++; goto _out;} if (!--m->row_description_count)  m->cs = 397; else  m->cs = 356; }
	goto _again;
tr415:
#line 82 "pg_fsm.rl"
	{ if (f->ready_for_query_state(u, pg_ready_for_query_state_inerror)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr416:
#line 80 "pg_fsm.rl"
	{ if (f->ready_for_query_state(u, pg_ready_for_query_state_idle)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr417:
#line 83 "pg_fsm.rl"
	{ if (f->ready_for_query_state(u, pg_ready_for_query_state_intrans)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr421:
#line 32 "pg_fsm.rl"
	{ if (f->copy_done(u)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
tr429:
#line 59 "pg_fsm.rl"
	{ if (f->no_data(u)) {p++;  m->cs = 397; goto _out;} }
	goto st397;
st397:
	if ( ++p == pe )
		goto _test_eof397;
case 397:
#line 566 "pg_fsm.c"
	switch( (*p) ) {
		case 49u: goto st1;
		case 50u: goto st5;
		case 51u: goto st9;
		case 65u: goto st13;
		case 67u: goto st25;
		case 68u: goto st31;
		case 69u: goto st41;
		case 72u: goto st83;
		case 73u: goto st91;
		case 75u: goto st95;
		case 78u: goto st107;
		case 82u: goto st111;
		case 83u: goto st127;
		case 84u: goto st350;
		case 86u: goto st376;
		case 90u: goto st380;
		case 99u: goto st385;
		case 100u: goto st389;
		case 110u: goto st393;
	}
	goto st0;
st0:
 m->cs = 0;
	goto _out;
tr451:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 1; goto _out;} m->string = NULL; }
	goto st1;
st1:
	if ( ++p == pe )
		goto _test_eof1;
case 1:
#line 600 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st2;
	goto st0;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 0u )
		goto st3;
	goto st0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	if ( (*p) == 0u )
		goto st4;
	goto st0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	if ( (*p) == 4u )
		goto tr4;
	goto st0;
tr452:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 5; goto _out;} m->string = NULL; }
	goto st5;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
#line 633 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st6;
	goto st0;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
	if ( (*p) == 0u )
		goto st7;
	goto st0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	if ( (*p) == 0u )
		goto st8;
	goto st0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	if ( (*p) == 4u )
		goto tr8;
	goto st0;
tr453:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 9; goto _out;} m->string = NULL; }
	goto st9;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
#line 666 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st10;
	goto st0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	if ( (*p) == 0u )
		goto st11;
	goto st0;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
	if ( (*p) == 0u )
		goto st12;
	goto st0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	if ( (*p) == 4u )
		goto tr12;
	goto st0;
tr454:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 13; goto _out;} m->string = NULL; }
	goto st13;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
#line 699 "pg_fsm.c"
	goto tr13;
tr13:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st14;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
#line 709 "pg_fsm.c"
	goto tr14;
tr14:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st15;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
#line 719 "pg_fsm.c"
	goto tr15;
tr15:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 729 "pg_fsm.c"
	goto tr16;
tr16:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 62 "pg_fsm.rl"
	{ if (f->notification_response(u, m->int4 - 4)) {p++;  m->cs = 17; goto _out;} }
	goto st17;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
#line 741 "pg_fsm.c"
	goto tr17;
tr17:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st18;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
#line 751 "pg_fsm.c"
	goto tr18;
tr18:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st19;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
#line 761 "pg_fsm.c"
	goto tr19;
tr19:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st20;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
#line 771 "pg_fsm.c"
	goto tr20;
tr20:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 63 "pg_fsm.rl"
	{ if (f->notification_response_pid(u, m->int4)) {p++;  m->cs = 21; goto _out;} }
	goto st21;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
#line 783 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st0;
	goto tr21;
tr21:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
#line 795 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr22;
	goto tr21;
tr22:
#line 64 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->notification_response_relname(u, p - m->string, m->string)) {p++;  m->cs = 23; goto _out;} m->string = NULL; }
	goto st23;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
#line 807 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st0;
	goto tr23;
tr23:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st24;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
#line 819 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr24;
	goto tr23;
tr455:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 25; goto _out;} m->string = NULL; }
	goto st25;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
#line 831 "pg_fsm.c"
	goto tr25;
tr25:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st26;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
#line 841 "pg_fsm.c"
	goto tr26;
tr26:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st27;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
#line 851 "pg_fsm.c"
	goto tr27;
tr27:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st28;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
#line 861 "pg_fsm.c"
	goto tr28;
tr28:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 29 "pg_fsm.rl"
	{ if (f->command_complete(u, m->int4 - 4)) {p++;  m->cs = 29; goto _out;} }
	goto st29;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
#line 873 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st0;
	goto tr29;
tr29:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st30;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
#line 885 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr30;
	goto tr29;
tr456:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 31; goto _out;} m->string = NULL; }
	goto st31;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
#line 897 "pg_fsm.c"
	goto tr31;
tr31:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st32;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
#line 907 "pg_fsm.c"
	goto tr32;
tr32:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st33;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
#line 917 "pg_fsm.c"
	goto tr33;
tr33:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st34;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
#line 927 "pg_fsm.c"
	goto tr34;
tr34:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 35 "pg_fsm.rl"
	{ if (f->data_row(u, m->int4 - 4)) {p++;  m->cs = 35; goto _out;} }
	goto st35;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
#line 939 "pg_fsm.c"
	goto tr35;
tr35:
#line 57 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int2); m->int2 = 0; } m->int2 |= *p << ((2 << 2) * --m->i); }
	goto st36;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
#line 949 "pg_fsm.c"
	goto tr36;
tr36:
	 m->cs = 37;
#line 57 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int2); m->int2 = 0; } m->int2 |= *p << ((2 << 2) * --m->i); }
#line 34 "pg_fsm.rl"
	{ m->data_row_count = m->int2; if (f->data_row_count(u, m->data_row_count)) {p++; goto _out;} if (!m->data_row_count)  m->cs = 397; }
	goto _again;
tr410:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 56 "pg_fsm.rl"
	{ if (f->function_call_response(u, m->int4 - 4)) {p++;  m->cs = 37; goto _out;} }
	goto st37;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
#line 968 "pg_fsm.c"
	goto tr37;
tr37:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st38;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
#line 978 "pg_fsm.c"
	goto tr38;
tr38:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st39;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
#line 988 "pg_fsm.c"
	goto tr39;
tr39:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st40;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
#line 998 "pg_fsm.c"
	goto tr40;
tr40:
	 m->cs = 398;
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 84 "pg_fsm.rl"
	{ m->result_len = m->int4; if (f->result_len(u, m->result_len)) {p++; goto _out;} if (!m->result_len || m->result_len == (uint32_t)-1) { if (!m->data_row_count || !--m->data_row_count)  m->cs = 397; else  m->cs = 37; } }
	goto _again;
tr425:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 31 "pg_fsm.rl"
	{ m->result_len = m->int4 - 4; if (f->copy_data(u, m->result_len)) {p++;  m->cs = 398; goto _out;} }
	goto st398;
tr449:
	 m->cs = 398;
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
#line 85 "pg_fsm.rl"
	{ if (p == eof || !m->result_len--) { if (m->string && p - m->string > 0 && f->result_val(u, p - m->string, m->string)) {p++; goto _out;} m->string = NULL; if (m->result_len == (uint32_t)-1) { if (f->result_done(u)) {p++; goto _out;} p--; if (!m->data_row_count || !--m->data_row_count)  m->cs = 397; else  m->cs = 37; } } }
	goto _again;
st398:
	if ( ++p == pe )
		goto _test_eof398;
case 398:
#line 1024 "pg_fsm.c"
	goto tr449;
tr457:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 41; goto _out;} m->string = NULL; }
	goto st41;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
#line 1034 "pg_fsm.c"
	goto tr41;
tr41:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st42;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
#line 1044 "pg_fsm.c"
	goto tr42;
tr42:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st43;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
#line 1054 "pg_fsm.c"
	goto tr43;
tr43:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st44;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
#line 1064 "pg_fsm.c"
	goto tr44;
tr44:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 45 "pg_fsm.rl"
	{ if (f->error_response(u, m->int4 - 4)) {p++;  m->cs = 45; goto _out;} }
	goto st45;
tr126:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 60 "pg_fsm.rl"
	{ if (f->notice_response(u, m->int4 - 4)) {p++;  m->cs = 45; goto _out;} }
	goto st45;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
#line 1082 "pg_fsm.c"
	switch( (*p) ) {
		case 67u: goto st46;
		case 68u: goto st49;
		case 70u: goto st51;
		case 72u: goto st53;
		case 76u: goto st55;
		case 77u: goto st57;
		case 80u: goto st59;
		case 82u: goto st61;
		case 83u: goto st63;
		case 86u: goto st65;
		case 87u: goto st67;
		case 99u: goto st69;
		case 100u: goto st71;
		case 110u: goto st73;
		case 112u: goto st75;
		case 113u: goto st77;
		case 115u: goto st79;
		case 116u: goto st81;
	}
	goto st0;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
	if ( (*p) == 0u )
		goto st0;
	goto tr63;
tr63:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st47;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
#line 1119 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr64;
	goto tr63;
tr64:
#line 53 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_sqlstate(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr67:
#line 41 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_detail(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr69:
#line 42 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_file(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr71:
#line 44 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_hint(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr73:
#line 47 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_line(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr75:
#line 49 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_primary(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr77:
#line 54 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_statement(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr79:
#line 43 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_function(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr81:
#line 52 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_severity(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr83:
#line 48 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_nonlocalized(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr85:
#line 39 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_context(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr87:
#line 37 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_column(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr89:
#line 40 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_datatype(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr91:
#line 38 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_constraint(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr93:
#line 46 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_internal(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr95:
#line 50 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_query(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr97:
#line 51 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_schema(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
tr99:
#line 55 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_table(u, p - m->string, m->string)) {p++;  m->cs = 48; goto _out;} m->string = NULL; }
	goto st48;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
#line 1199 "pg_fsm.c"
	switch( (*p) ) {
		case 0u: goto st397;
		case 67u: goto st46;
		case 68u: goto st49;
		case 70u: goto st51;
		case 72u: goto st53;
		case 76u: goto st55;
		case 77u: goto st57;
		case 80u: goto st59;
		case 82u: goto st61;
		case 83u: goto st63;
		case 86u: goto st65;
		case 87u: goto st67;
		case 99u: goto st69;
		case 100u: goto st71;
		case 110u: goto st73;
		case 112u: goto st75;
		case 113u: goto st77;
		case 115u: goto st79;
		case 116u: goto st81;
	}
	goto st0;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
	if ( (*p) == 0u )
		goto st0;
	goto tr66;
tr66:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st50;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
#line 1237 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr67;
	goto tr66;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
	if ( (*p) == 0u )
		goto st0;
	goto tr68;
tr68:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st52;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
#line 1256 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr69;
	goto tr68;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
	if ( (*p) == 0u )
		goto st0;
	goto tr70;
tr70:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st54;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
#line 1275 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr71;
	goto tr70;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
	if ( (*p) == 0u )
		goto st0;
	goto tr72;
tr72:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st56;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
#line 1294 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr73;
	goto tr72;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
	if ( (*p) == 0u )
		goto st0;
	goto tr74;
tr74:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st58;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
#line 1313 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr75;
	goto tr74;
st59:
	if ( ++p == pe )
		goto _test_eof59;
case 59:
	if ( (*p) == 0u )
		goto st0;
	goto tr76;
tr76:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st60;
st60:
	if ( ++p == pe )
		goto _test_eof60;
case 60:
#line 1332 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr77;
	goto tr76;
st61:
	if ( ++p == pe )
		goto _test_eof61;
case 61:
	if ( (*p) == 0u )
		goto st0;
	goto tr78;
tr78:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st62;
st62:
	if ( ++p == pe )
		goto _test_eof62;
case 62:
#line 1351 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr79;
	goto tr78;
st63:
	if ( ++p == pe )
		goto _test_eof63;
case 63:
	if ( (*p) == 0u )
		goto st0;
	goto tr80;
tr80:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st64;
st64:
	if ( ++p == pe )
		goto _test_eof64;
case 64:
#line 1370 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr81;
	goto tr80;
st65:
	if ( ++p == pe )
		goto _test_eof65;
case 65:
	if ( (*p) == 0u )
		goto st0;
	goto tr82;
tr82:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st66;
st66:
	if ( ++p == pe )
		goto _test_eof66;
case 66:
#line 1389 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr83;
	goto tr82;
st67:
	if ( ++p == pe )
		goto _test_eof67;
case 67:
	if ( (*p) == 0u )
		goto st0;
	goto tr84;
tr84:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st68;
st68:
	if ( ++p == pe )
		goto _test_eof68;
case 68:
#line 1408 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr85;
	goto tr84;
st69:
	if ( ++p == pe )
		goto _test_eof69;
case 69:
	if ( (*p) == 0u )
		goto st0;
	goto tr86;
tr86:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st70;
st70:
	if ( ++p == pe )
		goto _test_eof70;
case 70:
#line 1427 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr87;
	goto tr86;
st71:
	if ( ++p == pe )
		goto _test_eof71;
case 71:
	if ( (*p) == 0u )
		goto st0;
	goto tr88;
tr88:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st72;
st72:
	if ( ++p == pe )
		goto _test_eof72;
case 72:
#line 1446 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr89;
	goto tr88;
st73:
	if ( ++p == pe )
		goto _test_eof73;
case 73:
	if ( (*p) == 0u )
		goto st0;
	goto tr90;
tr90:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st74;
st74:
	if ( ++p == pe )
		goto _test_eof74;
case 74:
#line 1465 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr91;
	goto tr90;
st75:
	if ( ++p == pe )
		goto _test_eof75;
case 75:
	if ( (*p) == 0u )
		goto st0;
	goto tr92;
tr92:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st76;
st76:
	if ( ++p == pe )
		goto _test_eof76;
case 76:
#line 1484 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr93;
	goto tr92;
st77:
	if ( ++p == pe )
		goto _test_eof77;
case 77:
	if ( (*p) == 0u )
		goto st0;
	goto tr94;
tr94:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st78;
st78:
	if ( ++p == pe )
		goto _test_eof78;
case 78:
#line 1503 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr95;
	goto tr94;
st79:
	if ( ++p == pe )
		goto _test_eof79;
case 79:
	if ( (*p) == 0u )
		goto st0;
	goto tr96;
tr96:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st80;
st80:
	if ( ++p == pe )
		goto _test_eof80;
case 80:
#line 1522 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr97;
	goto tr96;
st81:
	if ( ++p == pe )
		goto _test_eof81;
case 81:
	if ( (*p) == 0u )
		goto st0;
	goto tr98;
tr98:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st82;
st82:
	if ( ++p == pe )
		goto _test_eof82;
case 82:
#line 1541 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr99;
	goto tr98;
tr458:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 83; goto _out;} m->string = NULL; }
	goto st83;
st83:
	if ( ++p == pe )
		goto _test_eof83;
case 83:
#line 1553 "pg_fsm.c"
	goto tr100;
tr100:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st84;
st84:
	if ( ++p == pe )
		goto _test_eof84;
case 84:
#line 1563 "pg_fsm.c"
	goto tr101;
tr101:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st85;
st85:
	if ( ++p == pe )
		goto _test_eof85;
case 85:
#line 1573 "pg_fsm.c"
	goto tr102;
tr102:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st86;
st86:
	if ( ++p == pe )
		goto _test_eof86;
case 86:
#line 1583 "pg_fsm.c"
	goto tr103;
tr103:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 33 "pg_fsm.rl"
	{ if (f->copy_out_response(u, m->int4 - 4)) {p++;  m->cs = 87; goto _out;} }
	goto st87;
st87:
	if ( ++p == pe )
		goto _test_eof87;
case 87:
#line 1595 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st88;
	goto st0;
st88:
	if ( ++p == pe )
		goto _test_eof88;
case 88:
	goto st89;
st89:
	if ( ++p == pe )
		goto _test_eof89;
case 89:
	goto st399;
st399:
	if ( ++p == pe )
		goto _test_eof399;
case 399:
	switch( (*p) ) {
		case 0u: goto st90;
		case 49u: goto st1;
		case 50u: goto st5;
		case 51u: goto st9;
		case 65u: goto st13;
		case 67u: goto st25;
		case 68u: goto st31;
		case 69u: goto st41;
		case 72u: goto st83;
		case 73u: goto st91;
		case 75u: goto st95;
		case 78u: goto st107;
		case 82u: goto st111;
		case 83u: goto st127;
		case 84u: goto st350;
		case 86u: goto st376;
		case 90u: goto st380;
		case 99u: goto st385;
		case 100u: goto st389;
		case 110u: goto st393;
	}
	goto st0;
st90:
	if ( ++p == pe )
		goto _test_eof90;
case 90:
	if ( (*p) == 0u )
		goto st399;
	goto st0;
tr459:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 91; goto _out;} m->string = NULL; }
	goto st91;
st91:
	if ( ++p == pe )
		goto _test_eof91;
case 91:
#line 1651 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st92;
	goto st0;
st92:
	if ( ++p == pe )
		goto _test_eof92;
case 92:
	if ( (*p) == 0u )
		goto st93;
	goto st0;
st93:
	if ( ++p == pe )
		goto _test_eof93;
case 93:
	if ( (*p) == 0u )
		goto st94;
	goto st0;
st94:
	if ( ++p == pe )
		goto _test_eof94;
case 94:
	if ( (*p) == 4u )
		goto tr110;
	goto st0;
tr460:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 95; goto _out;} m->string = NULL; }
	goto st95;
st95:
	if ( ++p == pe )
		goto _test_eof95;
case 95:
#line 1684 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st96;
	goto st0;
st96:
	if ( ++p == pe )
		goto _test_eof96;
case 96:
	if ( (*p) == 0u )
		goto st97;
	goto st0;
st97:
	if ( ++p == pe )
		goto _test_eof97;
case 97:
	if ( (*p) == 0u )
		goto st98;
	goto st0;
st98:
	if ( ++p == pe )
		goto _test_eof98;
case 98:
	if ( (*p) == 12u )
		goto tr114;
	goto st0;
tr114:
#line 24 "pg_fsm.rl"
	{ if (f->backend_key_data(u)) {p++;  m->cs = 99; goto _out;} }
	goto st99;
st99:
	if ( ++p == pe )
		goto _test_eof99;
case 99:
#line 1717 "pg_fsm.c"
	goto tr115;
tr115:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st100;
st100:
	if ( ++p == pe )
		goto _test_eof100;
case 100:
#line 1727 "pg_fsm.c"
	goto tr116;
tr116:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st101;
st101:
	if ( ++p == pe )
		goto _test_eof101;
case 101:
#line 1737 "pg_fsm.c"
	goto tr117;
tr117:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st102;
st102:
	if ( ++p == pe )
		goto _test_eof102;
case 102:
#line 1747 "pg_fsm.c"
	goto tr118;
tr118:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 26 "pg_fsm.rl"
	{ if (f->backend_key_data_pid(u, m->int4)) {p++;  m->cs = 103; goto _out;} }
	goto st103;
st103:
	if ( ++p == pe )
		goto _test_eof103;
case 103:
#line 1759 "pg_fsm.c"
	goto tr119;
tr119:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st104;
st104:
	if ( ++p == pe )
		goto _test_eof104;
case 104:
#line 1769 "pg_fsm.c"
	goto tr120;
tr120:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st105;
st105:
	if ( ++p == pe )
		goto _test_eof105;
case 105:
#line 1779 "pg_fsm.c"
	goto tr121;
tr121:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st106;
st106:
	if ( ++p == pe )
		goto _test_eof106;
case 106:
#line 1789 "pg_fsm.c"
	goto tr122;
tr461:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 107; goto _out;} m->string = NULL; }
	goto st107;
st107:
	if ( ++p == pe )
		goto _test_eof107;
case 107:
#line 1799 "pg_fsm.c"
	goto tr123;
tr123:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st108;
st108:
	if ( ++p == pe )
		goto _test_eof108;
case 108:
#line 1809 "pg_fsm.c"
	goto tr124;
tr124:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st109;
st109:
	if ( ++p == pe )
		goto _test_eof109;
case 109:
#line 1819 "pg_fsm.c"
	goto tr125;
tr125:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st110;
st110:
	if ( ++p == pe )
		goto _test_eof110;
case 110:
#line 1829 "pg_fsm.c"
	goto tr126;
tr462:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 111; goto _out;} m->string = NULL; }
	goto st111;
st111:
	if ( ++p == pe )
		goto _test_eof111;
case 111:
#line 1839 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st112;
	goto st0;
st112:
	if ( ++p == pe )
		goto _test_eof112;
case 112:
	if ( (*p) == 0u )
		goto st113;
	goto st0;
st113:
	if ( ++p == pe )
		goto _test_eof113;
case 113:
	if ( (*p) == 0u )
		goto st114;
	goto st0;
st114:
	if ( ++p == pe )
		goto _test_eof114;
case 114:
	switch( (*p) ) {
		case 8u: goto st115;
		case 12u: goto st119;
	}
	goto st0;
st115:
	if ( ++p == pe )
		goto _test_eof115;
case 115:
	if ( (*p) == 0u )
		goto st116;
	goto st0;
st116:
	if ( ++p == pe )
		goto _test_eof116;
case 116:
	if ( (*p) == 0u )
		goto st117;
	goto st0;
st117:
	if ( ++p == pe )
		goto _test_eof117;
case 117:
	if ( (*p) == 0u )
		goto st118;
	goto st0;
st118:
	if ( ++p == pe )
		goto _test_eof118;
case 118:
	switch( (*p) ) {
		case 0u: goto tr135;
		case 3u: goto tr136;
	}
	goto st0;
st119:
	if ( ++p == pe )
		goto _test_eof119;
case 119:
	if ( (*p) == 0u )
		goto st120;
	goto st0;
st120:
	if ( ++p == pe )
		goto _test_eof120;
case 120:
	if ( (*p) == 0u )
		goto st121;
	goto st0;
st121:
	if ( ++p == pe )
		goto _test_eof121;
case 121:
	if ( (*p) == 0u )
		goto st122;
	goto st0;
st122:
	if ( ++p == pe )
		goto _test_eof122;
case 122:
	if ( (*p) == 5u )
		goto st123;
	goto st0;
st123:
	if ( ++p == pe )
		goto _test_eof123;
case 123:
	goto tr141;
tr141:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st124;
st124:
	if ( ++p == pe )
		goto _test_eof124;
case 124:
#line 1937 "pg_fsm.c"
	goto tr142;
tr142:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st125;
st125:
	if ( ++p == pe )
		goto _test_eof125;
case 125:
#line 1947 "pg_fsm.c"
	goto tr143;
tr143:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st126;
st126:
	if ( ++p == pe )
		goto _test_eof126;
case 126:
#line 1957 "pg_fsm.c"
	goto tr144;
tr144:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st400;
st400:
	if ( ++p == pe )
		goto _test_eof400;
case 400:
#line 1967 "pg_fsm.c"
	switch( (*p) ) {
		case 49u: goto tr451;
		case 50u: goto tr452;
		case 51u: goto tr453;
		case 65u: goto tr454;
		case 67u: goto tr455;
		case 68u: goto tr456;
		case 69u: goto tr457;
		case 72u: goto tr458;
		case 73u: goto tr459;
		case 75u: goto tr460;
		case 78u: goto tr461;
		case 82u: goto tr462;
		case 83u: goto tr463;
		case 84u: goto tr464;
		case 86u: goto tr465;
		case 90u: goto tr466;
		case 99u: goto tr467;
		case 100u: goto tr468;
		case 110u: goto tr469;
	}
	goto st0;
tr463:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 127; goto _out;} m->string = NULL; }
	goto st127;
st127:
	if ( ++p == pe )
		goto _test_eof127;
case 127:
#line 1998 "pg_fsm.c"
	goto tr145;
tr145:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st128;
st128:
	if ( ++p == pe )
		goto _test_eof128;
case 128:
#line 2008 "pg_fsm.c"
	goto tr146;
tr146:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st129;
st129:
	if ( ++p == pe )
		goto _test_eof129;
case 129:
#line 2018 "pg_fsm.c"
	goto tr147;
tr147:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st130;
st130:
	if ( ++p == pe )
		goto _test_eof130;
case 130:
#line 2028 "pg_fsm.c"
	goto tr148;
tr148:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 69 "pg_fsm.rl"
	{ if (f->parameter_status(u, m->int4 - 4)) {p++;  m->cs = 131; goto _out;} }
	goto st131;
st131:
	if ( ++p == pe )
		goto _test_eof131;
case 131:
#line 2040 "pg_fsm.c"
	switch( (*p) ) {
		case 65u: goto st132;
		case 67u: goto st150;
		case 68u: goto st167;
		case 73u: goto st208;
		case 83u: goto st265;
		case 84u: goto st340;
		case 97u: goto st132;
		case 99u: goto st150;
		case 100u: goto st167;
		case 105u: goto st208;
		case 115u: goto st265;
		case 116u: goto st340;
	}
	goto st0;
st132:
	if ( ++p == pe )
		goto _test_eof132;
case 132:
	switch( (*p) ) {
		case 80u: goto st133;
		case 112u: goto st133;
	}
	goto st0;
st133:
	if ( ++p == pe )
		goto _test_eof133;
case 133:
	switch( (*p) ) {
		case 80u: goto st134;
		case 112u: goto st134;
	}
	goto st0;
st134:
	if ( ++p == pe )
		goto _test_eof134;
case 134:
	switch( (*p) ) {
		case 76u: goto st135;
		case 108u: goto st135;
	}
	goto st0;
st135:
	if ( ++p == pe )
		goto _test_eof135;
case 135:
	switch( (*p) ) {
		case 73u: goto st136;
		case 105u: goto st136;
	}
	goto st0;
st136:
	if ( ++p == pe )
		goto _test_eof136;
case 136:
	switch( (*p) ) {
		case 67u: goto st137;
		case 99u: goto st137;
	}
	goto st0;
st137:
	if ( ++p == pe )
		goto _test_eof137;
case 137:
	switch( (*p) ) {
		case 65u: goto st138;
		case 97u: goto st138;
	}
	goto st0;
st138:
	if ( ++p == pe )
		goto _test_eof138;
case 138:
	switch( (*p) ) {
		case 84u: goto st139;
		case 116u: goto st139;
	}
	goto st0;
st139:
	if ( ++p == pe )
		goto _test_eof139;
case 139:
	switch( (*p) ) {
		case 73u: goto st140;
		case 105u: goto st140;
	}
	goto st0;
st140:
	if ( ++p == pe )
		goto _test_eof140;
case 140:
	switch( (*p) ) {
		case 79u: goto st141;
		case 111u: goto st141;
	}
	goto st0;
st141:
	if ( ++p == pe )
		goto _test_eof141;
case 141:
	switch( (*p) ) {
		case 78u: goto st142;
		case 110u: goto st142;
	}
	goto st0;
st142:
	if ( ++p == pe )
		goto _test_eof142;
case 142:
	if ( (*p) == 95u )
		goto st143;
	goto st0;
st143:
	if ( ++p == pe )
		goto _test_eof143;
case 143:
	switch( (*p) ) {
		case 78u: goto st144;
		case 110u: goto st144;
	}
	goto st0;
st144:
	if ( ++p == pe )
		goto _test_eof144;
case 144:
	switch( (*p) ) {
		case 65u: goto st145;
		case 97u: goto st145;
	}
	goto st0;
st145:
	if ( ++p == pe )
		goto _test_eof145;
case 145:
	switch( (*p) ) {
		case 77u: goto st146;
		case 109u: goto st146;
	}
	goto st0;
st146:
	if ( ++p == pe )
		goto _test_eof146;
case 146:
	switch( (*p) ) {
		case 69u: goto st147;
		case 101u: goto st147;
	}
	goto st0;
st147:
	if ( ++p == pe )
		goto _test_eof147;
case 147:
	if ( (*p) == 0u )
		goto st148;
	goto st0;
st148:
	if ( ++p == pe )
		goto _test_eof148;
case 148:
	if ( (*p) == 0u )
		goto st0;
	goto tr171;
tr171:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st149;
st149:
	if ( ++p == pe )
		goto _test_eof149;
case 149:
#line 2211 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr172;
	goto tr171;
st150:
	if ( ++p == pe )
		goto _test_eof150;
case 150:
	switch( (*p) ) {
		case 76u: goto st151;
		case 108u: goto st151;
	}
	goto st0;
st151:
	if ( ++p == pe )
		goto _test_eof151;
case 151:
	switch( (*p) ) {
		case 73u: goto st152;
		case 105u: goto st152;
	}
	goto st0;
st152:
	if ( ++p == pe )
		goto _test_eof152;
case 152:
	switch( (*p) ) {
		case 69u: goto st153;
		case 101u: goto st153;
	}
	goto st0;
st153:
	if ( ++p == pe )
		goto _test_eof153;
case 153:
	switch( (*p) ) {
		case 78u: goto st154;
		case 110u: goto st154;
	}
	goto st0;
st154:
	if ( ++p == pe )
		goto _test_eof154;
case 154:
	switch( (*p) ) {
		case 84u: goto st155;
		case 116u: goto st155;
	}
	goto st0;
st155:
	if ( ++p == pe )
		goto _test_eof155;
case 155:
	if ( (*p) == 95u )
		goto st156;
	goto st0;
st156:
	if ( ++p == pe )
		goto _test_eof156;
case 156:
	switch( (*p) ) {
		case 69u: goto st157;
		case 101u: goto st157;
	}
	goto st0;
st157:
	if ( ++p == pe )
		goto _test_eof157;
case 157:
	switch( (*p) ) {
		case 78u: goto st158;
		case 110u: goto st158;
	}
	goto st0;
st158:
	if ( ++p == pe )
		goto _test_eof158;
case 158:
	switch( (*p) ) {
		case 67u: goto st159;
		case 99u: goto st159;
	}
	goto st0;
st159:
	if ( ++p == pe )
		goto _test_eof159;
case 159:
	switch( (*p) ) {
		case 79u: goto st160;
		case 111u: goto st160;
	}
	goto st0;
st160:
	if ( ++p == pe )
		goto _test_eof160;
case 160:
	switch( (*p) ) {
		case 68u: goto st161;
		case 100u: goto st161;
	}
	goto st0;
st161:
	if ( ++p == pe )
		goto _test_eof161;
case 161:
	switch( (*p) ) {
		case 73u: goto st162;
		case 105u: goto st162;
	}
	goto st0;
st162:
	if ( ++p == pe )
		goto _test_eof162;
case 162:
	switch( (*p) ) {
		case 78u: goto st163;
		case 110u: goto st163;
	}
	goto st0;
st163:
	if ( ++p == pe )
		goto _test_eof163;
case 163:
	switch( (*p) ) {
		case 71u: goto st164;
		case 103u: goto st164;
	}
	goto st0;
st164:
	if ( ++p == pe )
		goto _test_eof164;
case 164:
	if ( (*p) == 0u )
		goto st165;
	goto st0;
st165:
	if ( ++p == pe )
		goto _test_eof165;
case 165:
	if ( (*p) == 0u )
		goto st0;
	goto tr188;
tr188:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st166;
st166:
	if ( ++p == pe )
		goto _test_eof166;
case 166:
#line 2361 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr189;
	goto tr188;
st167:
	if ( ++p == pe )
		goto _test_eof167;
case 167:
	switch( (*p) ) {
		case 65u: goto st168;
		case 69u: goto st178;
		case 97u: goto st168;
		case 101u: goto st178;
	}
	goto st0;
st168:
	if ( ++p == pe )
		goto _test_eof168;
case 168:
	switch( (*p) ) {
		case 84u: goto st169;
		case 116u: goto st169;
	}
	goto st0;
st169:
	if ( ++p == pe )
		goto _test_eof169;
case 169:
	switch( (*p) ) {
		case 69u: goto st170;
		case 101u: goto st170;
	}
	goto st0;
st170:
	if ( ++p == pe )
		goto _test_eof170;
case 170:
	switch( (*p) ) {
		case 83u: goto st171;
		case 115u: goto st171;
	}
	goto st0;
st171:
	if ( ++p == pe )
		goto _test_eof171;
case 171:
	switch( (*p) ) {
		case 84u: goto st172;
		case 116u: goto st172;
	}
	goto st0;
st172:
	if ( ++p == pe )
		goto _test_eof172;
case 172:
	switch( (*p) ) {
		case 89u: goto st173;
		case 121u: goto st173;
	}
	goto st0;
st173:
	if ( ++p == pe )
		goto _test_eof173;
case 173:
	switch( (*p) ) {
		case 76u: goto st174;
		case 108u: goto st174;
	}
	goto st0;
st174:
	if ( ++p == pe )
		goto _test_eof174;
case 174:
	switch( (*p) ) {
		case 69u: goto st175;
		case 101u: goto st175;
	}
	goto st0;
st175:
	if ( ++p == pe )
		goto _test_eof175;
case 175:
	if ( (*p) == 0u )
		goto st176;
	goto st0;
st176:
	if ( ++p == pe )
		goto _test_eof176;
case 176:
	if ( (*p) == 0u )
		goto st0;
	goto tr200;
tr200:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st177;
st177:
	if ( ++p == pe )
		goto _test_eof177;
case 177:
#line 2461 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr201;
	goto tr200;
st178:
	if ( ++p == pe )
		goto _test_eof178;
case 178:
	switch( (*p) ) {
		case 70u: goto st179;
		case 102u: goto st179;
	}
	goto st0;
st179:
	if ( ++p == pe )
		goto _test_eof179;
case 179:
	switch( (*p) ) {
		case 65u: goto st180;
		case 97u: goto st180;
	}
	goto st0;
st180:
	if ( ++p == pe )
		goto _test_eof180;
case 180:
	switch( (*p) ) {
		case 85u: goto st181;
		case 117u: goto st181;
	}
	goto st0;
st181:
	if ( ++p == pe )
		goto _test_eof181;
case 181:
	switch( (*p) ) {
		case 76u: goto st182;
		case 108u: goto st182;
	}
	goto st0;
st182:
	if ( ++p == pe )
		goto _test_eof182;
case 182:
	switch( (*p) ) {
		case 84u: goto st183;
		case 116u: goto st183;
	}
	goto st0;
st183:
	if ( ++p == pe )
		goto _test_eof183;
case 183:
	if ( (*p) == 95u )
		goto st184;
	goto st0;
st184:
	if ( ++p == pe )
		goto _test_eof184;
case 184:
	switch( (*p) ) {
		case 84u: goto st185;
		case 116u: goto st185;
	}
	goto st0;
st185:
	if ( ++p == pe )
		goto _test_eof185;
case 185:
	switch( (*p) ) {
		case 82u: goto st186;
		case 114u: goto st186;
	}
	goto st0;
st186:
	if ( ++p == pe )
		goto _test_eof186;
case 186:
	switch( (*p) ) {
		case 65u: goto st187;
		case 97u: goto st187;
	}
	goto st0;
st187:
	if ( ++p == pe )
		goto _test_eof187;
case 187:
	switch( (*p) ) {
		case 78u: goto st188;
		case 110u: goto st188;
	}
	goto st0;
st188:
	if ( ++p == pe )
		goto _test_eof188;
case 188:
	switch( (*p) ) {
		case 83u: goto st189;
		case 115u: goto st189;
	}
	goto st0;
st189:
	if ( ++p == pe )
		goto _test_eof189;
case 189:
	switch( (*p) ) {
		case 65u: goto st190;
		case 97u: goto st190;
	}
	goto st0;
st190:
	if ( ++p == pe )
		goto _test_eof190;
case 190:
	switch( (*p) ) {
		case 67u: goto st191;
		case 99u: goto st191;
	}
	goto st0;
st191:
	if ( ++p == pe )
		goto _test_eof191;
case 191:
	switch( (*p) ) {
		case 84u: goto st192;
		case 116u: goto st192;
	}
	goto st0;
st192:
	if ( ++p == pe )
		goto _test_eof192;
case 192:
	switch( (*p) ) {
		case 73u: goto st193;
		case 105u: goto st193;
	}
	goto st0;
st193:
	if ( ++p == pe )
		goto _test_eof193;
case 193:
	switch( (*p) ) {
		case 79u: goto st194;
		case 111u: goto st194;
	}
	goto st0;
st194:
	if ( ++p == pe )
		goto _test_eof194;
case 194:
	switch( (*p) ) {
		case 78u: goto st195;
		case 110u: goto st195;
	}
	goto st0;
st195:
	if ( ++p == pe )
		goto _test_eof195;
case 195:
	if ( (*p) == 95u )
		goto st196;
	goto st0;
st196:
	if ( ++p == pe )
		goto _test_eof196;
case 196:
	switch( (*p) ) {
		case 82u: goto st197;
		case 114u: goto st197;
	}
	goto st0;
st197:
	if ( ++p == pe )
		goto _test_eof197;
case 197:
	switch( (*p) ) {
		case 69u: goto st198;
		case 101u: goto st198;
	}
	goto st0;
st198:
	if ( ++p == pe )
		goto _test_eof198;
case 198:
	switch( (*p) ) {
		case 65u: goto st199;
		case 97u: goto st199;
	}
	goto st0;
st199:
	if ( ++p == pe )
		goto _test_eof199;
case 199:
	switch( (*p) ) {
		case 68u: goto st200;
		case 100u: goto st200;
	}
	goto st0;
st200:
	if ( ++p == pe )
		goto _test_eof200;
case 200:
	if ( (*p) == 95u )
		goto st201;
	goto st0;
st201:
	if ( ++p == pe )
		goto _test_eof201;
case 201:
	switch( (*p) ) {
		case 79u: goto st202;
		case 111u: goto st202;
	}
	goto st0;
st202:
	if ( ++p == pe )
		goto _test_eof202;
case 202:
	switch( (*p) ) {
		case 78u: goto st203;
		case 110u: goto st203;
	}
	goto st0;
st203:
	if ( ++p == pe )
		goto _test_eof203;
case 203:
	switch( (*p) ) {
		case 76u: goto st204;
		case 108u: goto st204;
	}
	goto st0;
st204:
	if ( ++p == pe )
		goto _test_eof204;
case 204:
	switch( (*p) ) {
		case 89u: goto st205;
		case 121u: goto st205;
	}
	goto st0;
st205:
	if ( ++p == pe )
		goto _test_eof205;
case 205:
	if ( (*p) == 0u )
		goto st206;
	goto st0;
st206:
	if ( ++p == pe )
		goto _test_eof206;
case 206:
	if ( (*p) == 0u )
		goto st0;
	goto tr230;
tr230:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st207;
st207:
	if ( ++p == pe )
		goto _test_eof207;
case 207:
#line 2724 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr231;
	goto tr230;
st208:
	if ( ++p == pe )
		goto _test_eof208;
case 208:
	switch( (*p) ) {
		case 78u: goto st209;
		case 83u: goto st252;
		case 110u: goto st209;
		case 115u: goto st252;
	}
	goto st0;
st209:
	if ( ++p == pe )
		goto _test_eof209;
case 209:
	switch( (*p) ) {
		case 84u: goto st210;
		case 95u: goto st238;
		case 116u: goto st210;
	}
	goto st0;
st210:
	if ( ++p == pe )
		goto _test_eof210;
case 210:
	switch( (*p) ) {
		case 69u: goto st211;
		case 101u: goto st211;
	}
	goto st0;
st211:
	if ( ++p == pe )
		goto _test_eof211;
case 211:
	switch( (*p) ) {
		case 71u: goto st212;
		case 82u: goto st227;
		case 103u: goto st212;
		case 114u: goto st227;
	}
	goto st0;
st212:
	if ( ++p == pe )
		goto _test_eof212;
case 212:
	switch( (*p) ) {
		case 69u: goto st213;
		case 101u: goto st213;
	}
	goto st0;
st213:
	if ( ++p == pe )
		goto _test_eof213;
case 213:
	switch( (*p) ) {
		case 82u: goto st214;
		case 114u: goto st214;
	}
	goto st0;
st214:
	if ( ++p == pe )
		goto _test_eof214;
case 214:
	if ( (*p) == 95u )
		goto st215;
	goto st0;
st215:
	if ( ++p == pe )
		goto _test_eof215;
case 215:
	switch( (*p) ) {
		case 68u: goto st216;
		case 100u: goto st216;
	}
	goto st0;
st216:
	if ( ++p == pe )
		goto _test_eof216;
case 216:
	switch( (*p) ) {
		case 65u: goto st217;
		case 97u: goto st217;
	}
	goto st0;
st217:
	if ( ++p == pe )
		goto _test_eof217;
case 217:
	switch( (*p) ) {
		case 84u: goto st218;
		case 116u: goto st218;
	}
	goto st0;
st218:
	if ( ++p == pe )
		goto _test_eof218;
case 218:
	switch( (*p) ) {
		case 69u: goto st219;
		case 101u: goto st219;
	}
	goto st0;
st219:
	if ( ++p == pe )
		goto _test_eof219;
case 219:
	switch( (*p) ) {
		case 84u: goto st220;
		case 116u: goto st220;
	}
	goto st0;
st220:
	if ( ++p == pe )
		goto _test_eof220;
case 220:
	switch( (*p) ) {
		case 73u: goto st221;
		case 105u: goto st221;
	}
	goto st0;
st221:
	if ( ++p == pe )
		goto _test_eof221;
case 221:
	switch( (*p) ) {
		case 77u: goto st222;
		case 109u: goto st222;
	}
	goto st0;
st222:
	if ( ++p == pe )
		goto _test_eof222;
case 222:
	switch( (*p) ) {
		case 69u: goto st223;
		case 101u: goto st223;
	}
	goto st0;
st223:
	if ( ++p == pe )
		goto _test_eof223;
case 223:
	switch( (*p) ) {
		case 83u: goto st224;
		case 115u: goto st224;
	}
	goto st0;
st224:
	if ( ++p == pe )
		goto _test_eof224;
case 224:
	if ( (*p) == 0u )
		goto st225;
	goto st0;
st225:
	if ( ++p == pe )
		goto _test_eof225;
case 225:
	if ( (*p) == 0u )
		goto st0;
	goto tr252;
tr252:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st226;
st226:
	if ( ++p == pe )
		goto _test_eof226;
case 226:
#line 2897 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr253;
	goto tr252;
st227:
	if ( ++p == pe )
		goto _test_eof227;
case 227:
	switch( (*p) ) {
		case 86u: goto st228;
		case 118u: goto st228;
	}
	goto st0;
st228:
	if ( ++p == pe )
		goto _test_eof228;
case 228:
	switch( (*p) ) {
		case 65u: goto st229;
		case 97u: goto st229;
	}
	goto st0;
st229:
	if ( ++p == pe )
		goto _test_eof229;
case 229:
	switch( (*p) ) {
		case 76u: goto st230;
		case 108u: goto st230;
	}
	goto st0;
st230:
	if ( ++p == pe )
		goto _test_eof230;
case 230:
	switch( (*p) ) {
		case 83u: goto st231;
		case 115u: goto st231;
	}
	goto st0;
st231:
	if ( ++p == pe )
		goto _test_eof231;
case 231:
	switch( (*p) ) {
		case 84u: goto st232;
		case 116u: goto st232;
	}
	goto st0;
st232:
	if ( ++p == pe )
		goto _test_eof232;
case 232:
	switch( (*p) ) {
		case 89u: goto st233;
		case 121u: goto st233;
	}
	goto st0;
st233:
	if ( ++p == pe )
		goto _test_eof233;
case 233:
	switch( (*p) ) {
		case 76u: goto st234;
		case 108u: goto st234;
	}
	goto st0;
st234:
	if ( ++p == pe )
		goto _test_eof234;
case 234:
	switch( (*p) ) {
		case 69u: goto st235;
		case 101u: goto st235;
	}
	goto st0;
st235:
	if ( ++p == pe )
		goto _test_eof235;
case 235:
	if ( (*p) == 0u )
		goto st236;
	goto st0;
st236:
	if ( ++p == pe )
		goto _test_eof236;
case 236:
	if ( (*p) == 0u )
		goto st0;
	goto tr263;
tr263:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st237;
st237:
	if ( ++p == pe )
		goto _test_eof237;
case 237:
#line 2995 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr264;
	goto tr263;
st238:
	if ( ++p == pe )
		goto _test_eof238;
case 238:
	switch( (*p) ) {
		case 72u: goto st239;
		case 104u: goto st239;
	}
	goto st0;
st239:
	if ( ++p == pe )
		goto _test_eof239;
case 239:
	switch( (*p) ) {
		case 79u: goto st240;
		case 111u: goto st240;
	}
	goto st0;
st240:
	if ( ++p == pe )
		goto _test_eof240;
case 240:
	switch( (*p) ) {
		case 84u: goto st241;
		case 116u: goto st241;
	}
	goto st0;
st241:
	if ( ++p == pe )
		goto _test_eof241;
case 241:
	if ( (*p) == 95u )
		goto st242;
	goto st0;
st242:
	if ( ++p == pe )
		goto _test_eof242;
case 242:
	switch( (*p) ) {
		case 83u: goto st243;
		case 115u: goto st243;
	}
	goto st0;
st243:
	if ( ++p == pe )
		goto _test_eof243;
case 243:
	switch( (*p) ) {
		case 84u: goto st244;
		case 116u: goto st244;
	}
	goto st0;
st244:
	if ( ++p == pe )
		goto _test_eof244;
case 244:
	switch( (*p) ) {
		case 65u: goto st245;
		case 97u: goto st245;
	}
	goto st0;
st245:
	if ( ++p == pe )
		goto _test_eof245;
case 245:
	switch( (*p) ) {
		case 78u: goto st246;
		case 110u: goto st246;
	}
	goto st0;
st246:
	if ( ++p == pe )
		goto _test_eof246;
case 246:
	switch( (*p) ) {
		case 68u: goto st247;
		case 100u: goto st247;
	}
	goto st0;
st247:
	if ( ++p == pe )
		goto _test_eof247;
case 247:
	switch( (*p) ) {
		case 66u: goto st248;
		case 98u: goto st248;
	}
	goto st0;
st248:
	if ( ++p == pe )
		goto _test_eof248;
case 248:
	switch( (*p) ) {
		case 89u: goto st249;
		case 121u: goto st249;
	}
	goto st0;
st249:
	if ( ++p == pe )
		goto _test_eof249;
case 249:
	if ( (*p) == 0u )
		goto st250;
	goto st0;
st250:
	if ( ++p == pe )
		goto _test_eof250;
case 250:
	if ( (*p) == 0u )
		goto st0;
	goto tr277;
tr277:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st251;
st251:
	if ( ++p == pe )
		goto _test_eof251;
case 251:
#line 3118 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr278;
	goto tr277;
st252:
	if ( ++p == pe )
		goto _test_eof252;
case 252:
	if ( (*p) == 95u )
		goto st253;
	goto st0;
st253:
	if ( ++p == pe )
		goto _test_eof253;
case 253:
	switch( (*p) ) {
		case 83u: goto st254;
		case 115u: goto st254;
	}
	goto st0;
st254:
	if ( ++p == pe )
		goto _test_eof254;
case 254:
	switch( (*p) ) {
		case 85u: goto st255;
		case 117u: goto st255;
	}
	goto st0;
st255:
	if ( ++p == pe )
		goto _test_eof255;
case 255:
	switch( (*p) ) {
		case 80u: goto st256;
		case 112u: goto st256;
	}
	goto st0;
st256:
	if ( ++p == pe )
		goto _test_eof256;
case 256:
	switch( (*p) ) {
		case 69u: goto st257;
		case 101u: goto st257;
	}
	goto st0;
st257:
	if ( ++p == pe )
		goto _test_eof257;
case 257:
	switch( (*p) ) {
		case 82u: goto st258;
		case 114u: goto st258;
	}
	goto st0;
st258:
	if ( ++p == pe )
		goto _test_eof258;
case 258:
	switch( (*p) ) {
		case 85u: goto st259;
		case 117u: goto st259;
	}
	goto st0;
st259:
	if ( ++p == pe )
		goto _test_eof259;
case 259:
	switch( (*p) ) {
		case 83u: goto st260;
		case 115u: goto st260;
	}
	goto st0;
st260:
	if ( ++p == pe )
		goto _test_eof260;
case 260:
	switch( (*p) ) {
		case 69u: goto st261;
		case 101u: goto st261;
	}
	goto st0;
st261:
	if ( ++p == pe )
		goto _test_eof261;
case 261:
	switch( (*p) ) {
		case 82u: goto st262;
		case 114u: goto st262;
	}
	goto st0;
st262:
	if ( ++p == pe )
		goto _test_eof262;
case 262:
	if ( (*p) == 0u )
		goto st263;
	goto st0;
st263:
	if ( ++p == pe )
		goto _test_eof263;
case 263:
	if ( (*p) == 0u )
		goto st0;
	goto tr290;
tr290:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st264;
st264:
	if ( ++p == pe )
		goto _test_eof264;
case 264:
#line 3232 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr291;
	goto tr290;
st265:
	if ( ++p == pe )
		goto _test_eof265;
case 265:
	switch( (*p) ) {
		case 69u: goto st266;
		case 84u: goto st312;
		case 101u: goto st266;
		case 116u: goto st312;
	}
	goto st0;
st266:
	if ( ++p == pe )
		goto _test_eof266;
case 266:
	switch( (*p) ) {
		case 82u: goto st267;
		case 83u: goto st291;
		case 114u: goto st267;
		case 115u: goto st291;
	}
	goto st0;
st267:
	if ( ++p == pe )
		goto _test_eof267;
case 267:
	switch( (*p) ) {
		case 86u: goto st268;
		case 118u: goto st268;
	}
	goto st0;
st268:
	if ( ++p == pe )
		goto _test_eof268;
case 268:
	switch( (*p) ) {
		case 69u: goto st269;
		case 101u: goto st269;
	}
	goto st0;
st269:
	if ( ++p == pe )
		goto _test_eof269;
case 269:
	switch( (*p) ) {
		case 82u: goto st270;
		case 114u: goto st270;
	}
	goto st0;
st270:
	if ( ++p == pe )
		goto _test_eof270;
case 270:
	if ( (*p) == 95u )
		goto st271;
	goto st0;
st271:
	if ( ++p == pe )
		goto _test_eof271;
case 271:
	switch( (*p) ) {
		case 69u: goto st272;
		case 86u: goto st282;
		case 101u: goto st272;
		case 118u: goto st282;
	}
	goto st0;
st272:
	if ( ++p == pe )
		goto _test_eof272;
case 272:
	switch( (*p) ) {
		case 78u: goto st273;
		case 110u: goto st273;
	}
	goto st0;
st273:
	if ( ++p == pe )
		goto _test_eof273;
case 273:
	switch( (*p) ) {
		case 67u: goto st274;
		case 99u: goto st274;
	}
	goto st0;
st274:
	if ( ++p == pe )
		goto _test_eof274;
case 274:
	switch( (*p) ) {
		case 79u: goto st275;
		case 111u: goto st275;
	}
	goto st0;
st275:
	if ( ++p == pe )
		goto _test_eof275;
case 275:
	switch( (*p) ) {
		case 68u: goto st276;
		case 100u: goto st276;
	}
	goto st0;
st276:
	if ( ++p == pe )
		goto _test_eof276;
case 276:
	switch( (*p) ) {
		case 73u: goto st277;
		case 105u: goto st277;
	}
	goto st0;
st277:
	if ( ++p == pe )
		goto _test_eof277;
case 277:
	switch( (*p) ) {
		case 78u: goto st278;
		case 110u: goto st278;
	}
	goto st0;
st278:
	if ( ++p == pe )
		goto _test_eof278;
case 278:
	switch( (*p) ) {
		case 71u: goto st279;
		case 103u: goto st279;
	}
	goto st0;
st279:
	if ( ++p == pe )
		goto _test_eof279;
case 279:
	if ( (*p) == 0u )
		goto st280;
	goto st0;
st280:
	if ( ++p == pe )
		goto _test_eof280;
case 280:
	if ( (*p) == 0u )
		goto st0;
	goto tr310;
tr310:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st281;
st281:
	if ( ++p == pe )
		goto _test_eof281;
case 281:
#line 3388 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr311;
	goto tr310;
st282:
	if ( ++p == pe )
		goto _test_eof282;
case 282:
	switch( (*p) ) {
		case 69u: goto st283;
		case 101u: goto st283;
	}
	goto st0;
st283:
	if ( ++p == pe )
		goto _test_eof283;
case 283:
	switch( (*p) ) {
		case 82u: goto st284;
		case 114u: goto st284;
	}
	goto st0;
st284:
	if ( ++p == pe )
		goto _test_eof284;
case 284:
	switch( (*p) ) {
		case 83u: goto st285;
		case 115u: goto st285;
	}
	goto st0;
st285:
	if ( ++p == pe )
		goto _test_eof285;
case 285:
	switch( (*p) ) {
		case 73u: goto st286;
		case 105u: goto st286;
	}
	goto st0;
st286:
	if ( ++p == pe )
		goto _test_eof286;
case 286:
	switch( (*p) ) {
		case 79u: goto st287;
		case 111u: goto st287;
	}
	goto st0;
st287:
	if ( ++p == pe )
		goto _test_eof287;
case 287:
	switch( (*p) ) {
		case 78u: goto st288;
		case 110u: goto st288;
	}
	goto st0;
st288:
	if ( ++p == pe )
		goto _test_eof288;
case 288:
	if ( (*p) == 0u )
		goto st289;
	goto st0;
st289:
	if ( ++p == pe )
		goto _test_eof289;
case 289:
	if ( (*p) == 0u )
		goto st0;
	goto tr319;
tr319:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st290;
st290:
	if ( ++p == pe )
		goto _test_eof290;
case 290:
#line 3468 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr320;
	goto tr319;
st291:
	if ( ++p == pe )
		goto _test_eof291;
case 291:
	switch( (*p) ) {
		case 83u: goto st292;
		case 115u: goto st292;
	}
	goto st0;
st292:
	if ( ++p == pe )
		goto _test_eof292;
case 292:
	switch( (*p) ) {
		case 73u: goto st293;
		case 105u: goto st293;
	}
	goto st0;
st293:
	if ( ++p == pe )
		goto _test_eof293;
case 293:
	switch( (*p) ) {
		case 79u: goto st294;
		case 111u: goto st294;
	}
	goto st0;
st294:
	if ( ++p == pe )
		goto _test_eof294;
case 294:
	switch( (*p) ) {
		case 78u: goto st295;
		case 110u: goto st295;
	}
	goto st0;
st295:
	if ( ++p == pe )
		goto _test_eof295;
case 295:
	if ( (*p) == 95u )
		goto st296;
	goto st0;
st296:
	if ( ++p == pe )
		goto _test_eof296;
case 296:
	switch( (*p) ) {
		case 65u: goto st297;
		case 97u: goto st297;
	}
	goto st0;
st297:
	if ( ++p == pe )
		goto _test_eof297;
case 297:
	switch( (*p) ) {
		case 85u: goto st298;
		case 117u: goto st298;
	}
	goto st0;
st298:
	if ( ++p == pe )
		goto _test_eof298;
case 298:
	switch( (*p) ) {
		case 84u: goto st299;
		case 116u: goto st299;
	}
	goto st0;
st299:
	if ( ++p == pe )
		goto _test_eof299;
case 299:
	switch( (*p) ) {
		case 72u: goto st300;
		case 104u: goto st300;
	}
	goto st0;
st300:
	if ( ++p == pe )
		goto _test_eof300;
case 300:
	switch( (*p) ) {
		case 79u: goto st301;
		case 111u: goto st301;
	}
	goto st0;
st301:
	if ( ++p == pe )
		goto _test_eof301;
case 301:
	switch( (*p) ) {
		case 82u: goto st302;
		case 114u: goto st302;
	}
	goto st0;
st302:
	if ( ++p == pe )
		goto _test_eof302;
case 302:
	switch( (*p) ) {
		case 73u: goto st303;
		case 105u: goto st303;
	}
	goto st0;
st303:
	if ( ++p == pe )
		goto _test_eof303;
case 303:
	switch( (*p) ) {
		case 90u: goto st304;
		case 122u: goto st304;
	}
	goto st0;
st304:
	if ( ++p == pe )
		goto _test_eof304;
case 304:
	switch( (*p) ) {
		case 65u: goto st305;
		case 97u: goto st305;
	}
	goto st0;
st305:
	if ( ++p == pe )
		goto _test_eof305;
case 305:
	switch( (*p) ) {
		case 84u: goto st306;
		case 116u: goto st306;
	}
	goto st0;
st306:
	if ( ++p == pe )
		goto _test_eof306;
case 306:
	switch( (*p) ) {
		case 73u: goto st307;
		case 105u: goto st307;
	}
	goto st0;
st307:
	if ( ++p == pe )
		goto _test_eof307;
case 307:
	switch( (*p) ) {
		case 79u: goto st308;
		case 111u: goto st308;
	}
	goto st0;
st308:
	if ( ++p == pe )
		goto _test_eof308;
case 308:
	switch( (*p) ) {
		case 78u: goto st309;
		case 110u: goto st309;
	}
	goto st0;
st309:
	if ( ++p == pe )
		goto _test_eof309;
case 309:
	if ( (*p) == 0u )
		goto st310;
	goto st0;
st310:
	if ( ++p == pe )
		goto _test_eof310;
case 310:
	if ( (*p) == 0u )
		goto st0;
	goto tr340;
tr340:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st311;
st311:
	if ( ++p == pe )
		goto _test_eof311;
case 311:
#line 3654 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr341;
	goto tr340;
st312:
	if ( ++p == pe )
		goto _test_eof312;
case 312:
	switch( (*p) ) {
		case 65u: goto st313;
		case 97u: goto st313;
	}
	goto st0;
st313:
	if ( ++p == pe )
		goto _test_eof313;
case 313:
	switch( (*p) ) {
		case 78u: goto st314;
		case 110u: goto st314;
	}
	goto st0;
st314:
	if ( ++p == pe )
		goto _test_eof314;
case 314:
	switch( (*p) ) {
		case 68u: goto st315;
		case 100u: goto st315;
	}
	goto st0;
st315:
	if ( ++p == pe )
		goto _test_eof315;
case 315:
	switch( (*p) ) {
		case 65u: goto st316;
		case 97u: goto st316;
	}
	goto st0;
st316:
	if ( ++p == pe )
		goto _test_eof316;
case 316:
	switch( (*p) ) {
		case 82u: goto st317;
		case 114u: goto st317;
	}
	goto st0;
st317:
	if ( ++p == pe )
		goto _test_eof317;
case 317:
	switch( (*p) ) {
		case 68u: goto st318;
		case 100u: goto st318;
	}
	goto st0;
st318:
	if ( ++p == pe )
		goto _test_eof318;
case 318:
	if ( (*p) == 95u )
		goto st319;
	goto st0;
st319:
	if ( ++p == pe )
		goto _test_eof319;
case 319:
	switch( (*p) ) {
		case 67u: goto st320;
		case 99u: goto st320;
	}
	goto st0;
st320:
	if ( ++p == pe )
		goto _test_eof320;
case 320:
	switch( (*p) ) {
		case 79u: goto st321;
		case 111u: goto st321;
	}
	goto st0;
st321:
	if ( ++p == pe )
		goto _test_eof321;
case 321:
	switch( (*p) ) {
		case 78u: goto st322;
		case 110u: goto st322;
	}
	goto st0;
st322:
	if ( ++p == pe )
		goto _test_eof322;
case 322:
	switch( (*p) ) {
		case 70u: goto st323;
		case 102u: goto st323;
	}
	goto st0;
st323:
	if ( ++p == pe )
		goto _test_eof323;
case 323:
	switch( (*p) ) {
		case 79u: goto st324;
		case 111u: goto st324;
	}
	goto st0;
st324:
	if ( ++p == pe )
		goto _test_eof324;
case 324:
	switch( (*p) ) {
		case 82u: goto st325;
		case 114u: goto st325;
	}
	goto st0;
st325:
	if ( ++p == pe )
		goto _test_eof325;
case 325:
	switch( (*p) ) {
		case 77u: goto st326;
		case 109u: goto st326;
	}
	goto st0;
st326:
	if ( ++p == pe )
		goto _test_eof326;
case 326:
	switch( (*p) ) {
		case 73u: goto st327;
		case 105u: goto st327;
	}
	goto st0;
st327:
	if ( ++p == pe )
		goto _test_eof327;
case 327:
	switch( (*p) ) {
		case 78u: goto st328;
		case 110u: goto st328;
	}
	goto st0;
st328:
	if ( ++p == pe )
		goto _test_eof328;
case 328:
	switch( (*p) ) {
		case 71u: goto st329;
		case 103u: goto st329;
	}
	goto st0;
st329:
	if ( ++p == pe )
		goto _test_eof329;
case 329:
	if ( (*p) == 95u )
		goto st330;
	goto st0;
st330:
	if ( ++p == pe )
		goto _test_eof330;
case 330:
	switch( (*p) ) {
		case 83u: goto st331;
		case 115u: goto st331;
	}
	goto st0;
st331:
	if ( ++p == pe )
		goto _test_eof331;
case 331:
	switch( (*p) ) {
		case 84u: goto st332;
		case 116u: goto st332;
	}
	goto st0;
st332:
	if ( ++p == pe )
		goto _test_eof332;
case 332:
	switch( (*p) ) {
		case 82u: goto st333;
		case 114u: goto st333;
	}
	goto st0;
st333:
	if ( ++p == pe )
		goto _test_eof333;
case 333:
	switch( (*p) ) {
		case 73u: goto st334;
		case 105u: goto st334;
	}
	goto st0;
st334:
	if ( ++p == pe )
		goto _test_eof334;
case 334:
	switch( (*p) ) {
		case 78u: goto st335;
		case 110u: goto st335;
	}
	goto st0;
st335:
	if ( ++p == pe )
		goto _test_eof335;
case 335:
	switch( (*p) ) {
		case 71u: goto st336;
		case 103u: goto st336;
	}
	goto st0;
st336:
	if ( ++p == pe )
		goto _test_eof336;
case 336:
	switch( (*p) ) {
		case 83u: goto st337;
		case 115u: goto st337;
	}
	goto st0;
st337:
	if ( ++p == pe )
		goto _test_eof337;
case 337:
	if ( (*p) == 0u )
		goto st338;
	goto st0;
st338:
	if ( ++p == pe )
		goto _test_eof338;
case 338:
	if ( (*p) == 0u )
		goto st0;
	goto tr368;
tr368:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st339;
st339:
	if ( ++p == pe )
		goto _test_eof339;
case 339:
#line 3901 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr369;
	goto tr368;
st340:
	if ( ++p == pe )
		goto _test_eof340;
case 340:
	switch( (*p) ) {
		case 73u: goto st341;
		case 105u: goto st341;
	}
	goto st0;
st341:
	if ( ++p == pe )
		goto _test_eof341;
case 341:
	switch( (*p) ) {
		case 77u: goto st342;
		case 109u: goto st342;
	}
	goto st0;
st342:
	if ( ++p == pe )
		goto _test_eof342;
case 342:
	switch( (*p) ) {
		case 69u: goto st343;
		case 101u: goto st343;
	}
	goto st0;
st343:
	if ( ++p == pe )
		goto _test_eof343;
case 343:
	switch( (*p) ) {
		case 90u: goto st344;
		case 122u: goto st344;
	}
	goto st0;
st344:
	if ( ++p == pe )
		goto _test_eof344;
case 344:
	switch( (*p) ) {
		case 79u: goto st345;
		case 111u: goto st345;
	}
	goto st0;
st345:
	if ( ++p == pe )
		goto _test_eof345;
case 345:
	switch( (*p) ) {
		case 78u: goto st346;
		case 110u: goto st346;
	}
	goto st0;
st346:
	if ( ++p == pe )
		goto _test_eof346;
case 346:
	switch( (*p) ) {
		case 69u: goto st347;
		case 101u: goto st347;
	}
	goto st0;
st347:
	if ( ++p == pe )
		goto _test_eof347;
case 347:
	if ( (*p) == 0u )
		goto st348;
	goto st0;
st348:
	if ( ++p == pe )
		goto _test_eof348;
case 348:
	if ( (*p) == 0u )
		goto st0;
	goto tr378;
tr378:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st349;
st349:
	if ( ++p == pe )
		goto _test_eof349;
case 349:
#line 3990 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr379;
	goto tr378;
tr464:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 350; goto _out;} m->string = NULL; }
	goto st350;
st350:
	if ( ++p == pe )
		goto _test_eof350;
case 350:
#line 4002 "pg_fsm.c"
	goto tr380;
tr380:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st351;
st351:
	if ( ++p == pe )
		goto _test_eof351;
case 351:
#line 4012 "pg_fsm.c"
	goto tr381;
tr381:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st352;
st352:
	if ( ++p == pe )
		goto _test_eof352;
case 352:
#line 4022 "pg_fsm.c"
	goto tr382;
tr382:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st353;
st353:
	if ( ++p == pe )
		goto _test_eof353;
case 353:
#line 4032 "pg_fsm.c"
	goto tr383;
tr383:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 90 "pg_fsm.rl"
	{ if (f->row_description(u, m->int4 - 4)) {p++;  m->cs = 354; goto _out;} }
	goto st354;
st354:
	if ( ++p == pe )
		goto _test_eof354;
case 354:
#line 4044 "pg_fsm.c"
	goto tr384;
tr384:
#line 57 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int2); m->int2 = 0; } m->int2 |= *p << ((2 << 2) * --m->i); }
	goto st355;
st355:
	if ( ++p == pe )
		goto _test_eof355;
case 355:
#line 4054 "pg_fsm.c"
	goto tr385;
tr385:
	 m->cs = 356;
#line 57 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int2); m->int2 = 0; } m->int2 |= *p << ((2 << 2) * --m->i); }
#line 88 "pg_fsm.rl"
	{ m->row_description_count = m->int2; if (f->row_description_count(u, m->row_description_count)) {p++; goto _out;} if (!m->row_description_count)  m->cs = 397; }
	goto _again;
st356:
	if ( ++p == pe )
		goto _test_eof356;
case 356:
#line 4067 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st0;
	goto tr386;
tr388:
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st357;
tr386:
#line 86 "pg_fsm.rl"
	{ if (f->row_description_beg(u)) {p++;  m->cs = 357; goto _out;} }
#line 96 "pg_fsm.rl"
	{ if (!m->string) m->string = p; }
	goto st357;
st357:
	if ( ++p == pe )
		goto _test_eof357;
case 357:
#line 4085 "pg_fsm.c"
	if ( (*p) == 0u )
		goto tr387;
	goto tr388;
tr387:
#line 93 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->row_description_name(u, p - m->string, m->string)) {p++;  m->cs = 358; goto _out;} m->string = NULL; }
	goto st358;
st358:
	if ( ++p == pe )
		goto _test_eof358;
case 358:
#line 4097 "pg_fsm.c"
	goto tr389;
tr389:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st359;
st359:
	if ( ++p == pe )
		goto _test_eof359;
case 359:
#line 4107 "pg_fsm.c"
	goto tr390;
tr390:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st360;
st360:
	if ( ++p == pe )
		goto _test_eof360;
case 360:
#line 4117 "pg_fsm.c"
	goto tr391;
tr391:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st361;
st361:
	if ( ++p == pe )
		goto _test_eof361;
case 361:
#line 4127 "pg_fsm.c"
	goto tr392;
tr392:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 95 "pg_fsm.rl"
	{ if (f->row_description_table(u, m->int4)) {p++;  m->cs = 362; goto _out;} }
	goto st362;
st362:
	if ( ++p == pe )
		goto _test_eof362;
case 362:
#line 4139 "pg_fsm.c"
	goto tr393;
tr393:
#line 57 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int2); m->int2 = 0; } m->int2 |= *p << ((2 << 2) * --m->i); }
	goto st363;
st363:
	if ( ++p == pe )
		goto _test_eof363;
case 363:
#line 4149 "pg_fsm.c"
	goto tr394;
tr394:
#line 57 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int2); m->int2 = 0; } m->int2 |= *p << ((2 << 2) * --m->i); }
#line 87 "pg_fsm.rl"
	{ if (f->row_description_column(u, m->int2)) {p++;  m->cs = 364; goto _out;} }
	goto st364;
st364:
	if ( ++p == pe )
		goto _test_eof364;
case 364:
#line 4161 "pg_fsm.c"
	goto tr395;
tr395:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st365;
st365:
	if ( ++p == pe )
		goto _test_eof365;
case 365:
#line 4171 "pg_fsm.c"
	goto tr396;
tr396:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st366;
st366:
	if ( ++p == pe )
		goto _test_eof366;
case 366:
#line 4181 "pg_fsm.c"
	goto tr397;
tr397:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st367;
st367:
	if ( ++p == pe )
		goto _test_eof367;
case 367:
#line 4191 "pg_fsm.c"
	goto tr398;
tr398:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 94 "pg_fsm.rl"
	{ if (f->row_description_oid(u, m->int4)) {p++;  m->cs = 368; goto _out;} }
	goto st368;
st368:
	if ( ++p == pe )
		goto _test_eof368;
case 368:
#line 4203 "pg_fsm.c"
	goto tr399;
tr399:
#line 57 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int2); m->int2 = 0; } m->int2 |= *p << ((2 << 2) * --m->i); }
	goto st369;
st369:
	if ( ++p == pe )
		goto _test_eof369;
case 369:
#line 4213 "pg_fsm.c"
	goto tr400;
tr400:
#line 57 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int2); m->int2 = 0; } m->int2 |= *p << ((2 << 2) * --m->i); }
#line 91 "pg_fsm.rl"
	{ if (f->row_description_length(u, m->int2)) {p++;  m->cs = 370; goto _out;} }
	goto st370;
st370:
	if ( ++p == pe )
		goto _test_eof370;
case 370:
#line 4225 "pg_fsm.c"
	goto tr401;
tr401:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st371;
st371:
	if ( ++p == pe )
		goto _test_eof371;
case 371:
#line 4235 "pg_fsm.c"
	goto tr402;
tr402:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st372;
st372:
	if ( ++p == pe )
		goto _test_eof372;
case 372:
#line 4245 "pg_fsm.c"
	goto tr403;
tr403:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st373;
st373:
	if ( ++p == pe )
		goto _test_eof373;
case 373:
#line 4255 "pg_fsm.c"
	goto tr404;
tr404:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
#line 92 "pg_fsm.rl"
	{ if (f->row_description_mod(u, m->int4)) {p++;  m->cs = 374; goto _out;} }
	goto st374;
st374:
	if ( ++p == pe )
		goto _test_eof374;
case 374:
#line 4267 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st375;
	goto st0;
st375:
	if ( ++p == pe )
		goto _test_eof375;
case 375:
	if ( (*p) == 0u )
		goto tr406;
	goto st0;
tr465:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 376; goto _out;} m->string = NULL; }
	goto st376;
st376:
	if ( ++p == pe )
		goto _test_eof376;
case 376:
#line 4286 "pg_fsm.c"
	goto tr407;
tr407:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st377;
st377:
	if ( ++p == pe )
		goto _test_eof377;
case 377:
#line 4296 "pg_fsm.c"
	goto tr408;
tr408:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st378;
st378:
	if ( ++p == pe )
		goto _test_eof378;
case 378:
#line 4306 "pg_fsm.c"
	goto tr409;
tr409:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st379;
st379:
	if ( ++p == pe )
		goto _test_eof379;
case 379:
#line 4316 "pg_fsm.c"
	goto tr410;
tr466:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 380; goto _out;} m->string = NULL; }
	goto st380;
st380:
	if ( ++p == pe )
		goto _test_eof380;
case 380:
#line 4326 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st381;
	goto st0;
st381:
	if ( ++p == pe )
		goto _test_eof381;
case 381:
	if ( (*p) == 0u )
		goto st382;
	goto st0;
st382:
	if ( ++p == pe )
		goto _test_eof382;
case 382:
	if ( (*p) == 0u )
		goto st383;
	goto st0;
st383:
	if ( ++p == pe )
		goto _test_eof383;
case 383:
	if ( (*p) == 5u )
		goto tr414;
	goto st0;
tr414:
#line 81 "pg_fsm.rl"
	{ if (f->ready_for_query(u)) {p++;  m->cs = 384; goto _out;} }
	goto st384;
st384:
	if ( ++p == pe )
		goto _test_eof384;
case 384:
#line 4359 "pg_fsm.c"
	switch( (*p) ) {
		case 69u: goto tr415;
		case 73u: goto tr416;
		case 84u: goto tr417;
	}
	goto st0;
tr467:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 385; goto _out;} m->string = NULL; }
	goto st385;
st385:
	if ( ++p == pe )
		goto _test_eof385;
case 385:
#line 4374 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st386;
	goto st0;
st386:
	if ( ++p == pe )
		goto _test_eof386;
case 386:
	if ( (*p) == 0u )
		goto st387;
	goto st0;
st387:
	if ( ++p == pe )
		goto _test_eof387;
case 387:
	if ( (*p) == 0u )
		goto st388;
	goto st0;
st388:
	if ( ++p == pe )
		goto _test_eof388;
case 388:
	if ( (*p) == 4u )
		goto tr421;
	goto st0;
tr468:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 389; goto _out;} m->string = NULL; }
	goto st389;
st389:
	if ( ++p == pe )
		goto _test_eof389;
case 389:
#line 4407 "pg_fsm.c"
	goto tr422;
tr422:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st390;
st390:
	if ( ++p == pe )
		goto _test_eof390;
case 390:
#line 4417 "pg_fsm.c"
	goto tr423;
tr423:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st391;
st391:
	if ( ++p == pe )
		goto _test_eof391;
case 391:
#line 4427 "pg_fsm.c"
	goto tr424;
tr424:
#line 58 "pg_fsm.rl"
	{ if (!m->i) { m->i = sizeof(m->int4); m->int4 = 0; } m->int4 |= *p << ((2 << 2) * --m->i); }
	goto st392;
st392:
	if ( ++p == pe )
		goto _test_eof392;
case 392:
#line 4437 "pg_fsm.c"
	goto tr425;
tr469:
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 393; goto _out;} m->string = NULL; }
	goto st393;
st393:
	if ( ++p == pe )
		goto _test_eof393;
case 393:
#line 4447 "pg_fsm.c"
	if ( (*p) == 0u )
		goto st394;
	goto st0;
st394:
	if ( ++p == pe )
		goto _test_eof394;
case 394:
	if ( (*p) == 0u )
		goto st395;
	goto st0;
st395:
	if ( ++p == pe )
		goto _test_eof395;
case 395:
	if ( (*p) == 0u )
		goto st396;
	goto st0;
st396:
	if ( ++p == pe )
		goto _test_eof396;
case 396:
	if ( (*p) == 4u )
		goto tr429;
	goto st0;
	}
	_test_eof397:  m->cs = 397; goto _test_eof; 
	_test_eof1:  m->cs = 1; goto _test_eof; 
	_test_eof2:  m->cs = 2; goto _test_eof; 
	_test_eof3:  m->cs = 3; goto _test_eof; 
	_test_eof4:  m->cs = 4; goto _test_eof; 
	_test_eof5:  m->cs = 5; goto _test_eof; 
	_test_eof6:  m->cs = 6; goto _test_eof; 
	_test_eof7:  m->cs = 7; goto _test_eof; 
	_test_eof8:  m->cs = 8; goto _test_eof; 
	_test_eof9:  m->cs = 9; goto _test_eof; 
	_test_eof10:  m->cs = 10; goto _test_eof; 
	_test_eof11:  m->cs = 11; goto _test_eof; 
	_test_eof12:  m->cs = 12; goto _test_eof; 
	_test_eof13:  m->cs = 13; goto _test_eof; 
	_test_eof14:  m->cs = 14; goto _test_eof; 
	_test_eof15:  m->cs = 15; goto _test_eof; 
	_test_eof16:  m->cs = 16; goto _test_eof; 
	_test_eof17:  m->cs = 17; goto _test_eof; 
	_test_eof18:  m->cs = 18; goto _test_eof; 
	_test_eof19:  m->cs = 19; goto _test_eof; 
	_test_eof20:  m->cs = 20; goto _test_eof; 
	_test_eof21:  m->cs = 21; goto _test_eof; 
	_test_eof22:  m->cs = 22; goto _test_eof; 
	_test_eof23:  m->cs = 23; goto _test_eof; 
	_test_eof24:  m->cs = 24; goto _test_eof; 
	_test_eof25:  m->cs = 25; goto _test_eof; 
	_test_eof26:  m->cs = 26; goto _test_eof; 
	_test_eof27:  m->cs = 27; goto _test_eof; 
	_test_eof28:  m->cs = 28; goto _test_eof; 
	_test_eof29:  m->cs = 29; goto _test_eof; 
	_test_eof30:  m->cs = 30; goto _test_eof; 
	_test_eof31:  m->cs = 31; goto _test_eof; 
	_test_eof32:  m->cs = 32; goto _test_eof; 
	_test_eof33:  m->cs = 33; goto _test_eof; 
	_test_eof34:  m->cs = 34; goto _test_eof; 
	_test_eof35:  m->cs = 35; goto _test_eof; 
	_test_eof36:  m->cs = 36; goto _test_eof; 
	_test_eof37:  m->cs = 37; goto _test_eof; 
	_test_eof38:  m->cs = 38; goto _test_eof; 
	_test_eof39:  m->cs = 39; goto _test_eof; 
	_test_eof40:  m->cs = 40; goto _test_eof; 
	_test_eof398:  m->cs = 398; goto _test_eof; 
	_test_eof41:  m->cs = 41; goto _test_eof; 
	_test_eof42:  m->cs = 42; goto _test_eof; 
	_test_eof43:  m->cs = 43; goto _test_eof; 
	_test_eof44:  m->cs = 44; goto _test_eof; 
	_test_eof45:  m->cs = 45; goto _test_eof; 
	_test_eof46:  m->cs = 46; goto _test_eof; 
	_test_eof47:  m->cs = 47; goto _test_eof; 
	_test_eof48:  m->cs = 48; goto _test_eof; 
	_test_eof49:  m->cs = 49; goto _test_eof; 
	_test_eof50:  m->cs = 50; goto _test_eof; 
	_test_eof51:  m->cs = 51; goto _test_eof; 
	_test_eof52:  m->cs = 52; goto _test_eof; 
	_test_eof53:  m->cs = 53; goto _test_eof; 
	_test_eof54:  m->cs = 54; goto _test_eof; 
	_test_eof55:  m->cs = 55; goto _test_eof; 
	_test_eof56:  m->cs = 56; goto _test_eof; 
	_test_eof57:  m->cs = 57; goto _test_eof; 
	_test_eof58:  m->cs = 58; goto _test_eof; 
	_test_eof59:  m->cs = 59; goto _test_eof; 
	_test_eof60:  m->cs = 60; goto _test_eof; 
	_test_eof61:  m->cs = 61; goto _test_eof; 
	_test_eof62:  m->cs = 62; goto _test_eof; 
	_test_eof63:  m->cs = 63; goto _test_eof; 
	_test_eof64:  m->cs = 64; goto _test_eof; 
	_test_eof65:  m->cs = 65; goto _test_eof; 
	_test_eof66:  m->cs = 66; goto _test_eof; 
	_test_eof67:  m->cs = 67; goto _test_eof; 
	_test_eof68:  m->cs = 68; goto _test_eof; 
	_test_eof69:  m->cs = 69; goto _test_eof; 
	_test_eof70:  m->cs = 70; goto _test_eof; 
	_test_eof71:  m->cs = 71; goto _test_eof; 
	_test_eof72:  m->cs = 72; goto _test_eof; 
	_test_eof73:  m->cs = 73; goto _test_eof; 
	_test_eof74:  m->cs = 74; goto _test_eof; 
	_test_eof75:  m->cs = 75; goto _test_eof; 
	_test_eof76:  m->cs = 76; goto _test_eof; 
	_test_eof77:  m->cs = 77; goto _test_eof; 
	_test_eof78:  m->cs = 78; goto _test_eof; 
	_test_eof79:  m->cs = 79; goto _test_eof; 
	_test_eof80:  m->cs = 80; goto _test_eof; 
	_test_eof81:  m->cs = 81; goto _test_eof; 
	_test_eof82:  m->cs = 82; goto _test_eof; 
	_test_eof83:  m->cs = 83; goto _test_eof; 
	_test_eof84:  m->cs = 84; goto _test_eof; 
	_test_eof85:  m->cs = 85; goto _test_eof; 
	_test_eof86:  m->cs = 86; goto _test_eof; 
	_test_eof87:  m->cs = 87; goto _test_eof; 
	_test_eof88:  m->cs = 88; goto _test_eof; 
	_test_eof89:  m->cs = 89; goto _test_eof; 
	_test_eof399:  m->cs = 399; goto _test_eof; 
	_test_eof90:  m->cs = 90; goto _test_eof; 
	_test_eof91:  m->cs = 91; goto _test_eof; 
	_test_eof92:  m->cs = 92; goto _test_eof; 
	_test_eof93:  m->cs = 93; goto _test_eof; 
	_test_eof94:  m->cs = 94; goto _test_eof; 
	_test_eof95:  m->cs = 95; goto _test_eof; 
	_test_eof96:  m->cs = 96; goto _test_eof; 
	_test_eof97:  m->cs = 97; goto _test_eof; 
	_test_eof98:  m->cs = 98; goto _test_eof; 
	_test_eof99:  m->cs = 99; goto _test_eof; 
	_test_eof100:  m->cs = 100; goto _test_eof; 
	_test_eof101:  m->cs = 101; goto _test_eof; 
	_test_eof102:  m->cs = 102; goto _test_eof; 
	_test_eof103:  m->cs = 103; goto _test_eof; 
	_test_eof104:  m->cs = 104; goto _test_eof; 
	_test_eof105:  m->cs = 105; goto _test_eof; 
	_test_eof106:  m->cs = 106; goto _test_eof; 
	_test_eof107:  m->cs = 107; goto _test_eof; 
	_test_eof108:  m->cs = 108; goto _test_eof; 
	_test_eof109:  m->cs = 109; goto _test_eof; 
	_test_eof110:  m->cs = 110; goto _test_eof; 
	_test_eof111:  m->cs = 111; goto _test_eof; 
	_test_eof112:  m->cs = 112; goto _test_eof; 
	_test_eof113:  m->cs = 113; goto _test_eof; 
	_test_eof114:  m->cs = 114; goto _test_eof; 
	_test_eof115:  m->cs = 115; goto _test_eof; 
	_test_eof116:  m->cs = 116; goto _test_eof; 
	_test_eof117:  m->cs = 117; goto _test_eof; 
	_test_eof118:  m->cs = 118; goto _test_eof; 
	_test_eof119:  m->cs = 119; goto _test_eof; 
	_test_eof120:  m->cs = 120; goto _test_eof; 
	_test_eof121:  m->cs = 121; goto _test_eof; 
	_test_eof122:  m->cs = 122; goto _test_eof; 
	_test_eof123:  m->cs = 123; goto _test_eof; 
	_test_eof124:  m->cs = 124; goto _test_eof; 
	_test_eof125:  m->cs = 125; goto _test_eof; 
	_test_eof126:  m->cs = 126; goto _test_eof; 
	_test_eof400:  m->cs = 400; goto _test_eof; 
	_test_eof127:  m->cs = 127; goto _test_eof; 
	_test_eof128:  m->cs = 128; goto _test_eof; 
	_test_eof129:  m->cs = 129; goto _test_eof; 
	_test_eof130:  m->cs = 130; goto _test_eof; 
	_test_eof131:  m->cs = 131; goto _test_eof; 
	_test_eof132:  m->cs = 132; goto _test_eof; 
	_test_eof133:  m->cs = 133; goto _test_eof; 
	_test_eof134:  m->cs = 134; goto _test_eof; 
	_test_eof135:  m->cs = 135; goto _test_eof; 
	_test_eof136:  m->cs = 136; goto _test_eof; 
	_test_eof137:  m->cs = 137; goto _test_eof; 
	_test_eof138:  m->cs = 138; goto _test_eof; 
	_test_eof139:  m->cs = 139; goto _test_eof; 
	_test_eof140:  m->cs = 140; goto _test_eof; 
	_test_eof141:  m->cs = 141; goto _test_eof; 
	_test_eof142:  m->cs = 142; goto _test_eof; 
	_test_eof143:  m->cs = 143; goto _test_eof; 
	_test_eof144:  m->cs = 144; goto _test_eof; 
	_test_eof145:  m->cs = 145; goto _test_eof; 
	_test_eof146:  m->cs = 146; goto _test_eof; 
	_test_eof147:  m->cs = 147; goto _test_eof; 
	_test_eof148:  m->cs = 148; goto _test_eof; 
	_test_eof149:  m->cs = 149; goto _test_eof; 
	_test_eof150:  m->cs = 150; goto _test_eof; 
	_test_eof151:  m->cs = 151; goto _test_eof; 
	_test_eof152:  m->cs = 152; goto _test_eof; 
	_test_eof153:  m->cs = 153; goto _test_eof; 
	_test_eof154:  m->cs = 154; goto _test_eof; 
	_test_eof155:  m->cs = 155; goto _test_eof; 
	_test_eof156:  m->cs = 156; goto _test_eof; 
	_test_eof157:  m->cs = 157; goto _test_eof; 
	_test_eof158:  m->cs = 158; goto _test_eof; 
	_test_eof159:  m->cs = 159; goto _test_eof; 
	_test_eof160:  m->cs = 160; goto _test_eof; 
	_test_eof161:  m->cs = 161; goto _test_eof; 
	_test_eof162:  m->cs = 162; goto _test_eof; 
	_test_eof163:  m->cs = 163; goto _test_eof; 
	_test_eof164:  m->cs = 164; goto _test_eof; 
	_test_eof165:  m->cs = 165; goto _test_eof; 
	_test_eof166:  m->cs = 166; goto _test_eof; 
	_test_eof167:  m->cs = 167; goto _test_eof; 
	_test_eof168:  m->cs = 168; goto _test_eof; 
	_test_eof169:  m->cs = 169; goto _test_eof; 
	_test_eof170:  m->cs = 170; goto _test_eof; 
	_test_eof171:  m->cs = 171; goto _test_eof; 
	_test_eof172:  m->cs = 172; goto _test_eof; 
	_test_eof173:  m->cs = 173; goto _test_eof; 
	_test_eof174:  m->cs = 174; goto _test_eof; 
	_test_eof175:  m->cs = 175; goto _test_eof; 
	_test_eof176:  m->cs = 176; goto _test_eof; 
	_test_eof177:  m->cs = 177; goto _test_eof; 
	_test_eof178:  m->cs = 178; goto _test_eof; 
	_test_eof179:  m->cs = 179; goto _test_eof; 
	_test_eof180:  m->cs = 180; goto _test_eof; 
	_test_eof181:  m->cs = 181; goto _test_eof; 
	_test_eof182:  m->cs = 182; goto _test_eof; 
	_test_eof183:  m->cs = 183; goto _test_eof; 
	_test_eof184:  m->cs = 184; goto _test_eof; 
	_test_eof185:  m->cs = 185; goto _test_eof; 
	_test_eof186:  m->cs = 186; goto _test_eof; 
	_test_eof187:  m->cs = 187; goto _test_eof; 
	_test_eof188:  m->cs = 188; goto _test_eof; 
	_test_eof189:  m->cs = 189; goto _test_eof; 
	_test_eof190:  m->cs = 190; goto _test_eof; 
	_test_eof191:  m->cs = 191; goto _test_eof; 
	_test_eof192:  m->cs = 192; goto _test_eof; 
	_test_eof193:  m->cs = 193; goto _test_eof; 
	_test_eof194:  m->cs = 194; goto _test_eof; 
	_test_eof195:  m->cs = 195; goto _test_eof; 
	_test_eof196:  m->cs = 196; goto _test_eof; 
	_test_eof197:  m->cs = 197; goto _test_eof; 
	_test_eof198:  m->cs = 198; goto _test_eof; 
	_test_eof199:  m->cs = 199; goto _test_eof; 
	_test_eof200:  m->cs = 200; goto _test_eof; 
	_test_eof201:  m->cs = 201; goto _test_eof; 
	_test_eof202:  m->cs = 202; goto _test_eof; 
	_test_eof203:  m->cs = 203; goto _test_eof; 
	_test_eof204:  m->cs = 204; goto _test_eof; 
	_test_eof205:  m->cs = 205; goto _test_eof; 
	_test_eof206:  m->cs = 206; goto _test_eof; 
	_test_eof207:  m->cs = 207; goto _test_eof; 
	_test_eof208:  m->cs = 208; goto _test_eof; 
	_test_eof209:  m->cs = 209; goto _test_eof; 
	_test_eof210:  m->cs = 210; goto _test_eof; 
	_test_eof211:  m->cs = 211; goto _test_eof; 
	_test_eof212:  m->cs = 212; goto _test_eof; 
	_test_eof213:  m->cs = 213; goto _test_eof; 
	_test_eof214:  m->cs = 214; goto _test_eof; 
	_test_eof215:  m->cs = 215; goto _test_eof; 
	_test_eof216:  m->cs = 216; goto _test_eof; 
	_test_eof217:  m->cs = 217; goto _test_eof; 
	_test_eof218:  m->cs = 218; goto _test_eof; 
	_test_eof219:  m->cs = 219; goto _test_eof; 
	_test_eof220:  m->cs = 220; goto _test_eof; 
	_test_eof221:  m->cs = 221; goto _test_eof; 
	_test_eof222:  m->cs = 222; goto _test_eof; 
	_test_eof223:  m->cs = 223; goto _test_eof; 
	_test_eof224:  m->cs = 224; goto _test_eof; 
	_test_eof225:  m->cs = 225; goto _test_eof; 
	_test_eof226:  m->cs = 226; goto _test_eof; 
	_test_eof227:  m->cs = 227; goto _test_eof; 
	_test_eof228:  m->cs = 228; goto _test_eof; 
	_test_eof229:  m->cs = 229; goto _test_eof; 
	_test_eof230:  m->cs = 230; goto _test_eof; 
	_test_eof231:  m->cs = 231; goto _test_eof; 
	_test_eof232:  m->cs = 232; goto _test_eof; 
	_test_eof233:  m->cs = 233; goto _test_eof; 
	_test_eof234:  m->cs = 234; goto _test_eof; 
	_test_eof235:  m->cs = 235; goto _test_eof; 
	_test_eof236:  m->cs = 236; goto _test_eof; 
	_test_eof237:  m->cs = 237; goto _test_eof; 
	_test_eof238:  m->cs = 238; goto _test_eof; 
	_test_eof239:  m->cs = 239; goto _test_eof; 
	_test_eof240:  m->cs = 240; goto _test_eof; 
	_test_eof241:  m->cs = 241; goto _test_eof; 
	_test_eof242:  m->cs = 242; goto _test_eof; 
	_test_eof243:  m->cs = 243; goto _test_eof; 
	_test_eof244:  m->cs = 244; goto _test_eof; 
	_test_eof245:  m->cs = 245; goto _test_eof; 
	_test_eof246:  m->cs = 246; goto _test_eof; 
	_test_eof247:  m->cs = 247; goto _test_eof; 
	_test_eof248:  m->cs = 248; goto _test_eof; 
	_test_eof249:  m->cs = 249; goto _test_eof; 
	_test_eof250:  m->cs = 250; goto _test_eof; 
	_test_eof251:  m->cs = 251; goto _test_eof; 
	_test_eof252:  m->cs = 252; goto _test_eof; 
	_test_eof253:  m->cs = 253; goto _test_eof; 
	_test_eof254:  m->cs = 254; goto _test_eof; 
	_test_eof255:  m->cs = 255; goto _test_eof; 
	_test_eof256:  m->cs = 256; goto _test_eof; 
	_test_eof257:  m->cs = 257; goto _test_eof; 
	_test_eof258:  m->cs = 258; goto _test_eof; 
	_test_eof259:  m->cs = 259; goto _test_eof; 
	_test_eof260:  m->cs = 260; goto _test_eof; 
	_test_eof261:  m->cs = 261; goto _test_eof; 
	_test_eof262:  m->cs = 262; goto _test_eof; 
	_test_eof263:  m->cs = 263; goto _test_eof; 
	_test_eof264:  m->cs = 264; goto _test_eof; 
	_test_eof265:  m->cs = 265; goto _test_eof; 
	_test_eof266:  m->cs = 266; goto _test_eof; 
	_test_eof267:  m->cs = 267; goto _test_eof; 
	_test_eof268:  m->cs = 268; goto _test_eof; 
	_test_eof269:  m->cs = 269; goto _test_eof; 
	_test_eof270:  m->cs = 270; goto _test_eof; 
	_test_eof271:  m->cs = 271; goto _test_eof; 
	_test_eof272:  m->cs = 272; goto _test_eof; 
	_test_eof273:  m->cs = 273; goto _test_eof; 
	_test_eof274:  m->cs = 274; goto _test_eof; 
	_test_eof275:  m->cs = 275; goto _test_eof; 
	_test_eof276:  m->cs = 276; goto _test_eof; 
	_test_eof277:  m->cs = 277; goto _test_eof; 
	_test_eof278:  m->cs = 278; goto _test_eof; 
	_test_eof279:  m->cs = 279; goto _test_eof; 
	_test_eof280:  m->cs = 280; goto _test_eof; 
	_test_eof281:  m->cs = 281; goto _test_eof; 
	_test_eof282:  m->cs = 282; goto _test_eof; 
	_test_eof283:  m->cs = 283; goto _test_eof; 
	_test_eof284:  m->cs = 284; goto _test_eof; 
	_test_eof285:  m->cs = 285; goto _test_eof; 
	_test_eof286:  m->cs = 286; goto _test_eof; 
	_test_eof287:  m->cs = 287; goto _test_eof; 
	_test_eof288:  m->cs = 288; goto _test_eof; 
	_test_eof289:  m->cs = 289; goto _test_eof; 
	_test_eof290:  m->cs = 290; goto _test_eof; 
	_test_eof291:  m->cs = 291; goto _test_eof; 
	_test_eof292:  m->cs = 292; goto _test_eof; 
	_test_eof293:  m->cs = 293; goto _test_eof; 
	_test_eof294:  m->cs = 294; goto _test_eof; 
	_test_eof295:  m->cs = 295; goto _test_eof; 
	_test_eof296:  m->cs = 296; goto _test_eof; 
	_test_eof297:  m->cs = 297; goto _test_eof; 
	_test_eof298:  m->cs = 298; goto _test_eof; 
	_test_eof299:  m->cs = 299; goto _test_eof; 
	_test_eof300:  m->cs = 300; goto _test_eof; 
	_test_eof301:  m->cs = 301; goto _test_eof; 
	_test_eof302:  m->cs = 302; goto _test_eof; 
	_test_eof303:  m->cs = 303; goto _test_eof; 
	_test_eof304:  m->cs = 304; goto _test_eof; 
	_test_eof305:  m->cs = 305; goto _test_eof; 
	_test_eof306:  m->cs = 306; goto _test_eof; 
	_test_eof307:  m->cs = 307; goto _test_eof; 
	_test_eof308:  m->cs = 308; goto _test_eof; 
	_test_eof309:  m->cs = 309; goto _test_eof; 
	_test_eof310:  m->cs = 310; goto _test_eof; 
	_test_eof311:  m->cs = 311; goto _test_eof; 
	_test_eof312:  m->cs = 312; goto _test_eof; 
	_test_eof313:  m->cs = 313; goto _test_eof; 
	_test_eof314:  m->cs = 314; goto _test_eof; 
	_test_eof315:  m->cs = 315; goto _test_eof; 
	_test_eof316:  m->cs = 316; goto _test_eof; 
	_test_eof317:  m->cs = 317; goto _test_eof; 
	_test_eof318:  m->cs = 318; goto _test_eof; 
	_test_eof319:  m->cs = 319; goto _test_eof; 
	_test_eof320:  m->cs = 320; goto _test_eof; 
	_test_eof321:  m->cs = 321; goto _test_eof; 
	_test_eof322:  m->cs = 322; goto _test_eof; 
	_test_eof323:  m->cs = 323; goto _test_eof; 
	_test_eof324:  m->cs = 324; goto _test_eof; 
	_test_eof325:  m->cs = 325; goto _test_eof; 
	_test_eof326:  m->cs = 326; goto _test_eof; 
	_test_eof327:  m->cs = 327; goto _test_eof; 
	_test_eof328:  m->cs = 328; goto _test_eof; 
	_test_eof329:  m->cs = 329; goto _test_eof; 
	_test_eof330:  m->cs = 330; goto _test_eof; 
	_test_eof331:  m->cs = 331; goto _test_eof; 
	_test_eof332:  m->cs = 332; goto _test_eof; 
	_test_eof333:  m->cs = 333; goto _test_eof; 
	_test_eof334:  m->cs = 334; goto _test_eof; 
	_test_eof335:  m->cs = 335; goto _test_eof; 
	_test_eof336:  m->cs = 336; goto _test_eof; 
	_test_eof337:  m->cs = 337; goto _test_eof; 
	_test_eof338:  m->cs = 338; goto _test_eof; 
	_test_eof339:  m->cs = 339; goto _test_eof; 
	_test_eof340:  m->cs = 340; goto _test_eof; 
	_test_eof341:  m->cs = 341; goto _test_eof; 
	_test_eof342:  m->cs = 342; goto _test_eof; 
	_test_eof343:  m->cs = 343; goto _test_eof; 
	_test_eof344:  m->cs = 344; goto _test_eof; 
	_test_eof345:  m->cs = 345; goto _test_eof; 
	_test_eof346:  m->cs = 346; goto _test_eof; 
	_test_eof347:  m->cs = 347; goto _test_eof; 
	_test_eof348:  m->cs = 348; goto _test_eof; 
	_test_eof349:  m->cs = 349; goto _test_eof; 
	_test_eof350:  m->cs = 350; goto _test_eof; 
	_test_eof351:  m->cs = 351; goto _test_eof; 
	_test_eof352:  m->cs = 352; goto _test_eof; 
	_test_eof353:  m->cs = 353; goto _test_eof; 
	_test_eof354:  m->cs = 354; goto _test_eof; 
	_test_eof355:  m->cs = 355; goto _test_eof; 
	_test_eof356:  m->cs = 356; goto _test_eof; 
	_test_eof357:  m->cs = 357; goto _test_eof; 
	_test_eof358:  m->cs = 358; goto _test_eof; 
	_test_eof359:  m->cs = 359; goto _test_eof; 
	_test_eof360:  m->cs = 360; goto _test_eof; 
	_test_eof361:  m->cs = 361; goto _test_eof; 
	_test_eof362:  m->cs = 362; goto _test_eof; 
	_test_eof363:  m->cs = 363; goto _test_eof; 
	_test_eof364:  m->cs = 364; goto _test_eof; 
	_test_eof365:  m->cs = 365; goto _test_eof; 
	_test_eof366:  m->cs = 366; goto _test_eof; 
	_test_eof367:  m->cs = 367; goto _test_eof; 
	_test_eof368:  m->cs = 368; goto _test_eof; 
	_test_eof369:  m->cs = 369; goto _test_eof; 
	_test_eof370:  m->cs = 370; goto _test_eof; 
	_test_eof371:  m->cs = 371; goto _test_eof; 
	_test_eof372:  m->cs = 372; goto _test_eof; 
	_test_eof373:  m->cs = 373; goto _test_eof; 
	_test_eof374:  m->cs = 374; goto _test_eof; 
	_test_eof375:  m->cs = 375; goto _test_eof; 
	_test_eof376:  m->cs = 376; goto _test_eof; 
	_test_eof377:  m->cs = 377; goto _test_eof; 
	_test_eof378:  m->cs = 378; goto _test_eof; 
	_test_eof379:  m->cs = 379; goto _test_eof; 
	_test_eof380:  m->cs = 380; goto _test_eof; 
	_test_eof381:  m->cs = 381; goto _test_eof; 
	_test_eof382:  m->cs = 382; goto _test_eof; 
	_test_eof383:  m->cs = 383; goto _test_eof; 
	_test_eof384:  m->cs = 384; goto _test_eof; 
	_test_eof385:  m->cs = 385; goto _test_eof; 
	_test_eof386:  m->cs = 386; goto _test_eof; 
	_test_eof387:  m->cs = 387; goto _test_eof; 
	_test_eof388:  m->cs = 388; goto _test_eof; 
	_test_eof389:  m->cs = 389; goto _test_eof; 
	_test_eof390:  m->cs = 390; goto _test_eof; 
	_test_eof391:  m->cs = 391; goto _test_eof; 
	_test_eof392:  m->cs = 392; goto _test_eof; 
	_test_eof393:  m->cs = 393; goto _test_eof; 
	_test_eof394:  m->cs = 394; goto _test_eof; 
	_test_eof395:  m->cs = 395; goto _test_eof; 
	_test_eof396:  m->cs = 396; goto _test_eof; 

	_test_eof: {}
	if ( p == eof )
	{
	switch (  m->cs ) {
	case 400: 
#line 22 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->authentication_md5_password(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 29: 
	case 30: 
#line 30 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->command_complete_val(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 69: 
	case 70: 
#line 37 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_column(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 73: 
	case 74: 
#line 38 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_constraint(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 67: 
	case 68: 
#line 39 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_context(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 71: 
	case 72: 
#line 40 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_datatype(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 49: 
	case 50: 
#line 41 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_detail(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 51: 
	case 52: 
#line 42 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_file(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 61: 
	case 62: 
#line 43 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_function(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 53: 
	case 54: 
#line 44 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_hint(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 75: 
	case 76: 
#line 46 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_internal(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 55: 
	case 56: 
#line 47 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_line(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 65: 
	case 66: 
#line 48 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_nonlocalized(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 57: 
	case 58: 
#line 49 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_primary(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 77: 
	case 78: 
#line 50 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_query(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 79: 
	case 80: 
#line 51 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_schema(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 63: 
	case 64: 
#line 52 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_severity(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 46: 
	case 47: 
#line 53 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_sqlstate(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 59: 
	case 60: 
#line 54 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_statement(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 81: 
	case 82: 
#line 55 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->error_response_table(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 23: 
	case 24: 
#line 61 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->notification_response_extra(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; if (p != eof) if (f->notification_response_done(u)) {p++;  m->cs = 0; goto _out;} }
	break;
	case 21: 
	case 22: 
#line 64 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->notification_response_relname(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 148: 
	case 149: 
#line 65 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_application_name(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 165: 
	case 166: 
#line 66 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_client_encoding(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 176: 
	case 177: 
#line 67 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_datestyle(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 206: 
	case 207: 
#line 68 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_default_transaction_read_only(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 250: 
	case 251: 
#line 70 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_in_hot_standby(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 225: 
	case 226: 
#line 71 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_integer_datetimes(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 236: 
	case 237: 
#line 72 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_intervalstyle(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 263: 
	case 264: 
#line 73 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_is_superuser(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 280: 
	case 281: 
#line 74 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_server_encoding(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 289: 
	case 290: 
#line 75 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_server_version(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 310: 
	case 311: 
#line 76 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_session_authorization(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 338: 
	case 339: 
#line 77 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_standard_conforming_strings(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 348: 
	case 349: 
#line 78 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->parameter_status_timezone(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
	case 398: 
#line 85 "pg_fsm.rl"
	{ if (p == eof || !m->result_len--) { if (m->string && p - m->string > 0 && f->result_val(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; if (m->result_len == (uint32_t)-1) { if (f->result_done(u)) {p++;  m->cs = 0; goto _out;} p--; if (!m->data_row_count || !--m->data_row_count)  m->cs = 397; else  m->cs = 37; } } }
	break;
	case 356: 
	case 357: 
#line 93 "pg_fsm.rl"
	{ if (m->string && p - m->string > 0 && f->row_description_name(u, p - m->string, m->string)) {p++;  m->cs = 0; goto _out;} m->string = NULL; }
	break;
#line 5061 "pg_fsm.c"
	}
	}

	_out: {}
	}

#line 198 "pg_fsm.rl"
    if (!m->cs) (void)f->error(u, p - b, p);
    return p - b;
}

size_t pg_fsm_size(void) {
    return sizeof(pg_fsm_t);
}

void pg_fsm_init(pg_fsm_t *m) {
    
#line 5079 "pg_fsm.c"
	{
	 m->cs = pg_fsm_start;
	}

#line 208 "pg_fsm.rl"
}
