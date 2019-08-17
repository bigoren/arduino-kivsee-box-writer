/*
 * --------------------------------------------------------------------------------------------------------------------
 * The outpost station sketch for the RFID set match game
 * --------------------------------------------------------------------------------------------------------------------
 * This sketch uses the MFRC522 library; for further details see: https://github.com/miguelbalboa/rfid

 * @license Released into the public domain.
 * 
 * Typical pin layout used:
 * -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 *
 */

#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
// #include <FastLED.h>

// #define RING_LEDS 16
// #define RINGS     4
// #define NUM_LEDS (RING_LEDS*RINGS)
// #define DATA_PIN 4

// Define the array of leds
// CRGB leds[NUM_LEDS];
// byte master_state = 0x0; //Off=0, Pattern=1, Color=2
// #include "LED_control.h"

#define RST_PIN         9           // Configurable, see typical pin layout above
#define SS_PIN          10          // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN);  // Create MFRC522 instance
#include "MFRC522_func.h"

MFRC522::MIFARE_Key key;
//MFRC522::StatusCode status;
byte sector         = 1;
byte blockAddr      = 4;
byte dataBlock[]    = {
        0xFF, 0x00, 0xFF, 0xFF, //  byte 1 for color encoding
        0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0x02  // byte 15 for event track bit[0] = burnerot2018, bit[1] = contra2019
    };
byte trailerBlock   = 7;
byte buffer[18];
byte size = sizeof(buffer);
bool read_success, write_success, auth_success;
byte PICC_version;

unsigned int prevReadCard[4];
unsigned int readCard[4];

bool is_old_chip = false;
byte chip_color;    
byte event_track;    

void setup() {
    Serial.begin(115200); // Initialize serial communications with the PC
    while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
    SPI.begin();        // Init SPI bus
    mfrc522.PCD_Init(); // Init MFRC522 card
    mfrc522.PCD_DumpVersionToSerial();	// Show details of PCD - MFRC522 Card Reader details
    Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));
    // Prepare the key (used both as key A and as key B)
    // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }

    // Serial.println(F("Scan a MIFARE Classic PICC to demonstrate read and write."));
    // Serial.print(F("Using key (for A and B):"));
    //dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
    Serial.println("Kivsee box RFID tag writer");

    Serial.print(F("BEWARE: Data will be written to the PICC, in sector #1 blockAddr: "));
    Serial.println(blockAddr);

    // FastLED.addLeds<NEOPIXEL, DATA_PIN>(leds, NUM_LEDS);
    // FastLED.setBrightness(32);

    // state = state | VALID_STATE;
}

/**
 * Main loop.
 */
void loop() {

    // change this to encode chips with different colors from 0x1 to 0x5
    chip_color = 0x1;
    event_track = 0x2; // event track byte, bit[0] = burnerot2018, bit[1] = contra2019

    // advance leds first
    // set_leds(state, master_state);
    // FastLED.show();
    // FastLED.delay(20);
    
    PICC_version = 0;
    PICC_version = mfrc522.PCD_ReadRegister(MFRC522::VersionReg);
    // START RFID HANDLING
    // Look for new cards
    if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return;

    // get card uid
    Serial.print("found tag with ID: ");
    for (int i = 0; i < mfrc522.uid.size; i++) {  // for size of uid.size write uid.uidByte to readCard
      // remember previous card uid
      prevReadCard[i] = readCard[i];
      readCard[i] = mfrc522.uid.uidByte[i];
      Serial.print(readCard[i], HEX);
    }
    Serial.println();
    
    // get PICC card type
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    Serial.println(mfrc522.PICC_GetTypeName(piccType));

    // Check for compatibility
    if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        Serial.println(F("This sample only works with MIFARE Classic cards."));
        return;
    }

    // perform authentication to open communication
    auth_success = authenticate(trailerBlock, key);
    if (!auth_success) {
      Serial.println(F("Authentication failed"));
      return;
    }

    // read the tag to get coded information
    read_success = read_block(blockAddr, buffer, size);
    if (!read_success) {
      Serial.println(F("Initial read failed, closing connection"));
      // Halt PICC
      mfrc522.PICC_HaltA();
      // Stop encryption on PCD
      mfrc522.PCD_StopCrypto1();
      return;
    }
    else {
      // Show the whole sector as it currently is
      Serial.println(F("Current data in sector:"));
      mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
      Serial.println();
      
      is_old_chip = (buffer[0] != 0xFF);  // first byte not 0xFF means old chip format
      if (is_old_chip) {
        chip_color = buffer[1] & 0x0F; // remove valid and win bits from color byte
        Serial.print ("old chip found with color "); Serial.println(chip_color, HEX);
        event_track = 0x3; // marking the chip with burnerot bit as well as contra bit
      }
    }
    
    // FastLED.clear();
    // FastLED.show();

    // Authenticate using key B
    //Serial.println(F("Authenticating again using key B..."));
    //status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
    //if (status != MFRC522::STATUS_OK) {
    //    Serial.print(F("PCD_Authenticate() failed: "));
    //    Serial.println(mfrc522.GetStatusCodeName(status));
    //    return;
    //}

  
    dataBlock[1] = chip_color;
    dataBlock[15] = event_track;
    
    if (!UIDcompare(prevReadCard,readCard, 4)) {
      write_success = write_and_verify(blockAddr, dataBlock, buffer, size);
      if (!write_success) {
        Serial.println(F("write failed! aborting chip handling"));
        // Halt PICC
        mfrc522.PICC_HaltA();
        // Stop encryption on PCD
        mfrc522.PCD_StopCrypto1();
        return;
      }
      else {
        Serial.print(F("write worked, encoded chip with color 0x")); Serial.print(buffer[1]);
        Serial.print(F(" and event track byte 0x")); Serial.println(buffer[15]);
      }
    }
    else {
      Serial.println("Same UID, not writing anything");
      Serial.print(F("Chip encoded color is ")); Serial.println(buffer[1], HEX);
      Serial.print(F("Chip encoded event track byte is ")); Serial.println(buffer[15], HEX);
    }

    // Dump the sector data, good for debug
    //Serial.println(F("Current data in sector:"));
    //mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
    //Serial.println();

    // close the connection with the RFID
    // Halt PICC
    mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();

    // visual indication for a successful operation
    // fill_solid(leds, NUM_LEDS, CHSV(0, 0, 64));
    // FastLED.show();
       
    // hold everything in place for some time
    delay(200);
}
