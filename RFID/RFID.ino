#include <SPI.h>
#include <MFRC522.h>
#define SS_PIN 10
#define RST_PIN 9

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

int blockNum = 2;

byte blockData[16] = {"PillDealBro"};
byte bufferlen = 18;
byte readBlockData[18];

MFRC522::StatusCode status;

void setup() {

  Serial.begin(9600);
  SPI.begin();
  mfrc522.PCD_Init();
  Serial.println("Scan a MIFARE 1K Tag to write data...");
}

void loop() {
  for ( byte i = 0; i < 6; i++)
  {
    key.keyByte[i] = 0xFF;
  }

  if (! mfrc522.PICC_IsNewCardPresent())
  {
    return;
  }
  if ( ! mfrc522.PICC_ReadCardSerial())
  {
    return;
  }

  Serial.println("\nCard Detected");
  Serial.print(F("Card UID:"));

  for (byte i = 0; i < mfrc522.uid.size; i++)
  {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }

  Serial.print("\n");
  Serial.print(F("PICC type: "));

  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
  Serial.println("\n Writing to Data Block...");

  WritetoDB(blockNum, blockData);
  
  Serial.print("\n");
  Serial.println("Reading from Data Block...");
  
  ReadDataFromBlock(blockNum, readBlockData);
  mfrc522.PICC_DumpToSerial(&(mfrc522.uid));

  Serial.print("\n Data in block:");
  Serial.print(blockNum);
  Serial.print(" ---> ");

  for (int j = 0 ; j < 16; j++)
  {
    Serial.write(readBlockData[j]);
  }
  Serial.print("\n");
}

void  WritetoDB(int blockNum, byte blockData[])
{
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));

  if ( status != MFRC522::STATUS_OK)
  {
    Serial.print("Authentication failed for Write:  ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    
    return;
  }

  else
  {
    Serial.println("Authentication success");
  }

  status = mfrc522.MIFARE_Write(blockNum, blockData, 16);

  if ( status != MFRC522::STATUS_OK)
  {
    Serial.print("Writing to Block failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    
    return;
  }
  else
  {
    Serial.println("Data written succesfully");
  }

}

void ReadDataFromBlock(int blockNum, byte readBlockData[])
{
  byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockNum, &key, &(mfrc522.uid));
   
   if (status != MFRC522::STATUS_OK)
  {
     Serial.print("Authentication failed for Read: ");
     Serial.println(mfrc522.GetStatusCodeName(status));
     return;
  }
  
  else
  {
    Serial.println("Authentication success");
  }
  
  status = mfrc522.MIFARE_Read(blockNum,readBlockData,&bufferlen);
  
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print("Reading failed: ");
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else
  {
    Serial.println("Block was read successfully");  
  }
  
}

 
