"""
Postoje 4 tipa podataka za prikupljanje vise stavki u jednoj promenljivoj, u jeziku Python:
LISTA je kolekcija koja je uredjena i promenljiva. Dozvoljava duple clanove.
TUPLE je kolekcija koja je uredjena i nepromenljiva. Dozvoljava dupliranje clanova.
SET je kolekcija koja je neuredjena, nepromenljiva i neindeksirana. Nema dupliranih clanova.
DICTIONARY je zbirka koja je uredjena i promenljiva. Nema dupliranih clanova.

"""
#LISTE
#vise stavki u jednoj promenljivoj. Liste su jedan od 4 ugradjena tipa podataka u Pyrhonu, druga 3 su Tuple, Set i Dictionary
#prave se pomocu uglastih zagrada
lista = ["jabuka", "banana", "ananas"] #sto se stave uglaste zagrade, zna se da se radi o listama
print(lista)
#liste su indeksirane, uredjene, promenljive i dozvoljavaju duple vrijednosti. prva stavka ima indeks [0] druga index [1], itd
#svaka nova stavka u listi, ide na kraju liste
#listu mozemo da mijenjamo, dodajemo i uklanjamo stavke sa liste nakon sto je kreirana
lista = ["jabuka", "banana", "ananas", "jabuka", "banana"] #lista dozvoljava duple vrijednosti
print (lista)
print(len(lista)) #da bi smo odredili koliko stavki ima lista koristimo funkciju len()
lista1 = ["jabuka", "banana", "ananas"] #lista od str
lista2 = [1, 5, 6, 9, 100, -1999] #lista sacinjena od brojeva
lista3 = [True, True, False] #boolean lista
print(lista1)
print(lista2)
print(lista3)
kombinovana = ["slova", 123, -434, True, "pol", 34.456] #lista moze da sadrzi razlicite tipove podataka
print(kombinovana)
print(type(kombinovana)) #liste su definisane kao objekti sa tipom podataka 'list'
niz = list (("jabuka", 1234, True, "banana")) #konstruktor list() za kreiranje nove liste
print(niz)

#PRISTUP STAVKAMA LISTE 
#liste su indeskirane i pristupa im se preko indeksa, od 0 do beskonacno
lista4 = ["jabuka", "banana", "lubenica", "dinja", "ananas", "kivi"]
print(lista4[1]) #banana
print(lista4[0]) #jabuka
print(lista4[-1]) #poslednja stavka, kivi
print(lista4[-2]) #pretposlednja stavka, ananas
print(lista4[-3]) #treca stavka otpozadi, dinja
print(lista4[2:5]) #pocetni i zavrsni opseg, povratna vrednost je nova lista sa odabranim stavkama.
#napomena: pocetni indeks je uvek ukljucen, zavrsni indeks NIJE ukljucen
print(lista4[2:5]) # izlaz je nova lista sa indeksima 2,3,4 - lubenica, dinja, ananas
print(lista4[:5]) # od 0(ukjljuceno) do 5(nije ukljuceno): jabuka, banana, lubenica, dinja, ananas
print(lista4[2:]) #od 2(ukljuceno) pa do kraja: lubenica, dinja, ananas, kivi
print(lista4[-4:-1]) #od -4(ukljuceno) do -1(iskljuceno): lubenica, dinja, ananas
if "jabuka" in lista4: #provera da li stavka postoji u listi. mora se dati puni naziv stavke.
    print("stavka jabuka postoji u listi4")

#PROMENA STAVKI LISTE
#promena se vrsi preko inndeksa
lista5 = ["jabuka", "banana", "mango"]
print(lista5)
lista5[2] = "lubenica"
print(lista5)
lista6 = ["jedan", "dva", "tri", "cetiri", "pet", "sest"]
print(lista6)
lista6[1:4] = ["DVA", "TRI", "CETIRI"] #zameni stavke od 1(ukljuceno) do 4(nije ukljuceno): jedan DVA TRI CETIRI pet sest
print(lista6)
lista7 = ["jedan", "dva", "tri", "cetiri", "pet", "sest"]
print(lista7)
lista7[1:4] = ["DVA", "TRI", "CETIRI", "PET", "SEST"] #umecemo vise stavki nego sto hocemo da zamenimo, nove stavke ce biti umetnute pa ce izlaz biti
#jedan DVA TRI CETIRI PET SEST pet sest, duzina liste ce se promeniti
print(lista7)
lista8 = ["jedan", "dva", "tri", "cetiri", "pet", "sest"]
lista8[1:4] = ["dvatricetiri"] #umecemo manje stavki, naveli smo da menjamo 3 a unosiumo 1 vrednost. ta 1 vrednost uzima 3 mesta. pa je izlaz: jedan dvatricetiri pet sest
print(lista8)
lista9 = ["banana", "jabuka", "kivi"]
lista9.insert(2, "ananas") #ubacije novu stavku na dati indeks bez mijenjanja vec postojece stavke: banana, jabuka, ananas, kivi
print(lista9)

#DODAVANJE STAVKE LISTI
dod = ["jabuka", "banana", "tresnja"]
dod.append("visnja") #dodajemo stavku koja ide na kraj liste
print(dod)
dod.insert(1, "kruska") #umetanje stavki na dati indeks, ostale stavke se pomeraju udesno
print(dod) #jabuka kruska banana tresnja visnja
avanje = ["ananas", "kivi", "avokado"]
dod.extend(avanje) #spajamo dve liste i pravimo jednu. elementi iz avanje idu u listu dod, na kraju liste
print(dod) #jabuka kruska banana tresnnja visnja ananas kivi avokado
nelista = ("ananas", "kivi", "avokado") #ovo su elementi tuple a ne elementi liste
dod.extend(nelista) #spaja listu i set ili tuple ili dictionary, idu na kraju liste
print(dod) #jabuka kruska tresnja visnja ananas kivi avokado ananas kivi avokado

#UKLANJANJE ELEMENATA SA LISTE
dod.remove("banana") #uklanjamo bananu iz liste
print(dod) #sve bez banane
dod.remove("ananas") #uklanja ananas iz liste. imamo 2 pojavljivanja stavke ananas, uklanja se samo jedna, prva na koju program naidje a ide od indeksa 0
print(dod) #jabuka kruska tresnnja visnja kivi avokado ananas kivi avokado
dod.pop(1) #uklanja element sa navedenim indeksom u ovom slucaju je indeks 1, tj uklanja stavku kruska
print(dod) #jabuka tresnja visnja kivi avokado ananas
dod.pop() #ako ne navedemo indeks, metoda pop uklanja poslednju stavku
print(dod) #jabuka tresnja visnja kivi avokado ananas kivi
del dod[0] #takodje uklanja stavku sa navedenim indeksom
print(dod) #tresnja visnja kivi avokado ananas kivi
#del dod #ukoliko se ne navede indeks onda brise cijelu listu
#print dod - kada se pokrene program ovo ce izazvati gresku jer se uspesno izbrisala navedena lista. ne moze se istampati nesto sto ne postoji
print(dod)
dod.clear() #praznjenje liste, spisak i dalje ostaje ali nema sadrzaja. moze se stampati za razliku od metode del gde se javlja greska pri stampalju. ovo je praznjenje a del je brisnje
print(dod) # []

#PETLJA KROZ LISTU
petlja = ["jabuka", "banana", "ananas", "kivi"]
for x in petlja: #for kroz petlju
    print(x) #stampamo stavke u listi, svaka se stampa u novom redu
for i in range(len(petlja)): #drugi nacin preko range i len
    print(petlja[i])
i = 0 # i se postavlja na vrijednost prije while petlje
while i<len(petlja): #uslov while petlje
    print(petlja[i])
    i = i +1 #korak koji se uvecava za 1 ili za koliko mi zelimo
voce = ["banana", "jabuka", "kruska", "mango", "kivi"]
novalista = [] #pravimo praznu listu koja ce sadrzati neke od elemenata liste voce

for x in voce:  #ukoliko ima slovo a u bilo kojoj stavci prebaci je u listu novovoce. moze bilo koje slovo ili slog ili rec. pravi razliku izmedju malih i velikih slova.
    if "a" in x:
        novalista.append(x)
print(novalista) #povratna vrednost je nova lista, stara lista ostaje nepromenjena
lista = [y for y in voce if "i" in y] #newlist = [expression for item in iterable if condition == True]
print(lista)

auta = ["BMW", "audi", "mercedes", "jeep", "volvo", "saab"]
novaauta = [] #govorimo da je u pitanju lista

for x in auta:
    if "m" in x: #pravi razliku izmedju m i M. m - mercedes, M - BMW    
        novaauta.append(x)
print(novaauta)
nova = [x for x in auta if "a" in x]
print(nova)
nova2 = [x for x in auta if x!="mercedes"] #pravi novu listu sa stavkama koje nisu mercedes. mora pujno ime ne moze samo slovo ili deo imena stavke. stampaj sve sto je razlicito od mercedes
print(nova2)
slova = ["a", "b", "c", "d"]
istaslova = [x for x in slova]  #pravimo listu sa istim stavkama sa listom sa kojom zelimo
print(slova)
print(istaslova)
#ITERABLE
dosto = [b for b in range(100)]
print(dosto) #stampa sve brojeve od 0 do 100. ne ukljucuje 100 samo 99
dopedeset = [m for m in range(100) if m<=50] #stampa od 0 d0 100 ali samo brojeve manje ili jednake 50
print(dopedeset)
parni = [p for p in range(100) if p%2 == 0] #stampa sve parne brojeve od 0 do 100. ne ukljucuje broj 100
print(parni)
neparni = [n for n in range(100) if n%2 == 1 and n<50] #stampa neparne brojeve od 0 do 100, ali samo one koju su manje od 50
print(neparni)
auta = ["BMW", "audi", "mercedes", "jeep", "volvo", "saab", "alfaromeo"]
print(auta)
AUTA = [x.upper() for x in auta] #pije nego sto stavke kopiramo u novu listu mi mozemo da manipulisemo njima
print(AUTA)
slovno = ["c", "af", "haa", "baaa", "ads", "maaa"] #velika slova se sortiraju pre malih slova. npr rec na M ce biti prije rice na a, jer je M veliko, a A ce bit prije M
slovno.sort() # od a do w
print(slovno)
slovno.sort(reverse=True) #od w do a
print(slovno)
brojevno = [132, 123, 5433, 7568, 12,6, -12] # od -besk. do beskonacno
brojevno.sort()
print(brojevno)
brojevno.sort(reverse=True)  #od beskonacno do - besk.
print(brojevno)
imena = ["Faaa", "aaa", "Waaa", "baa"]
imena.sort()
print(imena) #predsnost imaju velika slova
imena.sort(key=str.lower)
print(imena) #uklanja prednost velikih slova, sortira se od a do w kako mala tako i velika slova.
auta = ["BMW", "audi", "mercedes", "jeep", "volvo", "saab"]
kopija = auta.copy() #prvi nacin kopiranja liste, sta god da radimo u listi auta nece se ovde odraziti
print(kopija)
kopija2 = list(auta) #drugi nacin kopiranja liste, sta god da radimo u listi auta nece se ovde odraziti
print(kopija2)
auta = ["BMW", "audi", "mercedes", "jeep", "volvo", "saab", "alfaromeo"]
auta2 = ["volcwagen", "peugeot", "opel", "skoda"]
svaauta = auta + auta2 #prvi nacin za spajanje dve ili vise lista
print(svaauta)
auta.extend(auta2) #listi auta pridruzi listu auta2. drugi nacin spajanja listi
print(auta)

#TUPLE
#tuple je kolekcija koja je uredjena i nepromenljiva
#pise se oblim zagradama ()
#stavke tuple su poredjane, nepromenljive i dozvoljavaju duple vrijednosti. kada kazemo poredjane to znaci da stavke imaju definisan redosled i taj redosled se nece mijenjati
#stavke su indeksirane. prva stavka ima indeks 0, druga 1, itd
#RAZLIKA IZMEDJU LISTE I TUPLE JE TA, STO JE LISTA PROMENLJIVA A TUPLE JE NEPROMENLJIVA.
prvituple = ("jabuka", "banana", "mango")
print(prvituple)
#tuple su nepromenljive, sto znaci da ne mozemo da menjamo, dodajemo ili uklanjamo stavke nakon sto je tuple napravljen
#tuple dozvoljavaju duple vrijednosti
drugituple = ("jabuka", "banana", "mango", "banana", "kivi", "mango")
print(drugituple)
print(len(drugituple)) #stampamo broj stavki
treci = ("jabuka")
print(type(treci))
treci = ("jabuka",) #ako pravimo tuple od 1 stavke, onda moramo zarez  da stavimo posle nje, inace pithon je prepoznaje kao str ne kao tuple
print(type(treci))
#tuple moze da sadrzi razlicite tipove podataka, str, bool, num
cetvrti = ("ABC", 34, True, -3.67, "muski")
print(cetvrti)
print(type(cetvrti))
#pristup stavkama se vrsi preko njihovih indeksa, prva stavka ima indeks 0, druga ima indeks 1, itd...
#negativno indeksiranje znaci znaci poceti od kraja, -1 je poslednja stavka, -2 je pretposlednja, itd...
kola = ("audi", "mercedes", "bmw", "opel")
print(kola[0]) #audi
print(kola[-1]) #opel
print(kola[1:3]) #mercedes, bmw, ukjlucuje polazni indeks, ne ukljucuje krajnji indeks. 1 ukljuceno 3 nije ukljuceno
print(kola[:3]) #audi mercedes bmw. stavka 3 nije ukljucena
print(kola[1:]) #mercedes bmw opel. spampa do kraja, stavka 1 ukljucena kao i krajnja
print(kola[-3:-1]) #mercedes, bmw. stavka -3 ukljucena, stavka -1 nije ukljucena 

if "mercedes" in kola: #provera da li odredjena stavka postoji u tuple. mora puno ime stavke
    print("stavka mercedes postoji u listi kola")
torka = ("jabuka", "banana", "kruska", "kivi")
print(torka)
listatorka = list(torka)
print(type(listatorka))
listatorka.append("mango")
print(listatorka)
torka = tuple(listatorka)
print(torka)

#posto je torka nepromenljiva, da bi smo promenili njene stavke imamo 2 nacina
#prvi nacin je prebacaj iz torke u listu, nakon odredjenih promjena vracamo listu u torku
torka = ("jedan", "dva", "tri", "cetiri", "pet")
print(type(torka)) #prvi nacin je da prebacimo torku u listu i onda da radimo sve kao sto bi radili i sa listom
lista = list(torka)
print(type(lista))
print(lista)
lista.append("sest")
torka = tuple(lista) #kada izvrsimo odgovarajuce promjene, vracamo listu u torku
print(torka)
#drugi nacin je da napravimo novu torku (jednu ili vise) sa odgovarajucim stavkama i da je dodamo vec postojecoj torki
torka1 = ("jedan", "dva", "tri", "deset", "pedeset")
torka2 = ("sezdeset")
print(type(torka2))
torka2 = ("sezdeset", ) #ako ne stavimo , na kraju stavke, python prepoznaje kao str ne kao torku
print(type(torka2))
torka1+=torka2
print(torka1)

#kako je torka nepromenljiva po prirodi, mi osim sto ne mozemo da dodajemo stavke ne mozemo ni da uklanjamo stavke
#kako za dodavanje tako postoje i 2 nacina za uklanjanje stavki
#prvi je promena torke u listu, pa liste u torku nakon odredjenog brisanja

torka3 = (12, 13, 14, 15, 16, 17, 18)
lista3 = list(torka3)
print(type(lista3))
lista3.remove(16) #moze samo jedna stavka ne moze dvije ili vise
print(lista3) #lista
torka3 = tuple(lista3)
print(torka3) #torka

#drugi nacin je potpuno brisanje torke
#del torka3
#print(torka3), vraca gresku jer je torka izbrisana u potpunosti

#RASPAKIVANJE TORKI
#torke su po automatizmu upakovane. u pythonu je dozvoljeno da izdvojimo vrednosti torke nazad u promenljive, tj. da raspakujemo torku
voce = ("jabuka", "banana", "malina")
(zelena, zuta, crvena) = voce #broj promenljivih mora da odgovara broju vrijednosti u torki
print(zelena)
print(zuta)
print(crvena)
print("------------------")
voce = ("jabuka", "banana", "malina", "lubenica", "jagoda")
(zelena, zuta, *crvena) = voce #broj promenljivih je manji od broja vrijednosti u torci. * vise vrijednosti ce biti dodijeljena kao lista
print(zelena)
print(zuta)
print(crvena)
print("-------------------")
voce = ("banana", "kruska", "kivi", "mango", "jabuka", "malina")
(zuta, *zelena, crvena) = voce
print(zuta)
print(zelena)
print(crvena)
print("--------------------")

#PETLJE KROZ TORKU
voce = ("banana", "kruska", "kivi", "mango", "jabuka", "malina")
print(voce)
for x in voce: #prvi nacin
    print(x)
print("--------------------")
for i in range(len(voce)): #drugi nacin
    print(voce[i])
print("--------------------")
j = 0
while j < len(voce): #treci nacin
    print(voce[j])
    j+=1

#SPAJANJE 2 ILI VISE TORKI
slogovi = ("ab", "cd", "ef", "gh")
brojevi = (1, 3, 5, 7, 9, 11)
bol = (True, ) #mora zarez da bi python prepoznao kao torku
spojeno = slogovi + brojevi + bol
print(spojeno)
ponavljanje = ("kako", "si")
ponavljanje = ponavljanje*5 #ponavljanje stavki vise puta u jednom tupleu
print(ponavljanje)

#SETOVI (SKUPOVI)
"""
Sluze za cuvanje vise stavki u jednoj promenljivoj
Skup je kolekcija koja je neuredjena, nepromenljiva i neindeksirana. Ne dozvoljavaju duple vrijednosti.
Neuredjeno znaci da stavke u skupu nemaju definisan redosled. Mogu se pojaviti svaki put u drugom redosledu i ne mozemo se na njih pozvati sa indeksom
Nepromenljivo znaci da stavke seta ne mozemo mijenjati nakon sto je set kreiran. Jedino mogu da se uklone ili dodaju nove stavke nakon kreiranja seta
Duplikati nisu dozvoljeni, tj ne mozemo imati dve stavke sa istom vrednoscu u jednom setu. NAPOMENA: Vrijednost 1 i True se smatraju vrednoscu u skupovima i tretiraju se kao duplikat.
Pisu se  {} zagradama
"""
skup = {"jabuka", "banana", 1, 2, True} #ne javlja gresku ali ne stampa True, samo broj 1. Da nema broja 1 stampao bi true
print(skup) #svaki put kada se program pokrene stampa se drugaciji raspored vrijednosti
#stavke se prikazuju nasumicnim redosledom jer set nema numerisana mesta za stavke
#ne moze se prsitupiti pomocu kjuca ili indeksa ali mozemo da prodjemo sa for petljom kroz elemente stavke
for x in skup:
    print(x)
print("jabuka" in skup) #true
print("kivi" in skup) #false
#kada je skup kreiran ne mozemo da menjamo stavke ali mozemo da dodajemo nove stavke ili da uklanjamo postojece stavke
skup.add("kivi") #koristi se za dodavanje jedne stavke u skup
print(skup)
skup2 = {"mango", "avokado", "mandarina"}
skup.update(skup2) #koristi se za dodavanje jednog skupa drugom. objekat unutar update ne mora da bude skup, moze da bude ili set ili lista ili torka
print(skup)
lista = ["mango", "avokado", "mandarina"]
skup.update(lista) #unutar update moze da bude i lista ili torka ili distriction
print(skup)
#da bi smo uklonili predmet iz stavke, koristimo metode remove() ili disvsrd()
skup2 = {"jedan", "dva", "tri", "cetiri", "pet"}
print(skup2)
skup2.remove("tri") #ukanja stavku. napomena: ukoliko stavka za uklanjanje ne postoji u setu, remove javlja tj pokrece gresku
print(skup2)
skup2.discard("dva") #uklanja stavku. napomena: ukoliko stavka zauklanjanje ne postoji u setu, discard ne pokrece gresku
print(skup2)
x = skup2.pop() #pop uklanja nasumicnu vrednost iz seta. svaka vrednost ima iste sanse da bude uklonjena
print(x)
print(skup2)
skup2.clear() #prazni sve stavke iz skupa
print(skup2)
del skup2 #brise ceo skup i kada se pokrene stampa vraca gresku
#print(skup2)
voce = {"jabuka", "banana", "kivi", "mango", "avokado", "kruska", "ananas", "lubenica"}
print(voce)
for x in voce:
    print(x)    

#PRIDRUZIVANJE 2 SETA
voce = {"jabuka", "banana", "kivi", "mango", "avokado", "kruska", "paprika", "ananas", "lubenica"}
povrce = {"paradajz","paprika", "tikva", "mango", "kruska"}
vocepovrce = voce.union(povrce) #metod unuion vraca novi skup koji je sacinjen od elemenata 2 skupa. uklanja duplikate
print(vocepovrce)
voce.update(povrce) #metoda update prebacije stavke iz jednog u drugi niz. ne pravi treci niz. uklanja duplikate 
print(voce)
voce.intersection_update(povrce) #stavke koje su prisutne u oba skupa (duplikati)
print(voce)
z =voce.intersection(povrce) #vraca novi SKUP koji je sacinjen od dupliranih elemenata iz oba skupa
print(z)
voce2 = {"jabuka", "banana", "kivi", "mango", "avokado", "kruska", "paprika", "ananas", "lubenica"}
voce2.symmetric_difference_update(povrce) #stavke koje nisu prisutne u oba skupa
print(voce2) 
t = voce2.symmetric_difference(povrce) #vraca novi SKUP koji je sacinjen od jedinstvenih elemenata oba skupa
print(t)
#vrijednost 1 i True smatraju se kao isti elementi i tretiraju se kao duplikati
"""Recnici sluze za cuvanje vrednosti podataka i rade po principu kljuc-vrednost
Recnik je uredjen, promenljiv i ne dozvoljava duplikate
Pisu se u vitivastim zagradama i imaju kljuceve i vrednosti kljuca
Stavkama recnika se pristupa preko njihovg kljuca
Stavke imaju definisan redosled i taj redosled se nece menjati
Recnici su promenljivi sto znaci da mozemo menjati, dodavati ili uklanjati stavke nakon sto je recnik kreiran
Recnici ne mogu imati 2 ili vise stavki sa istim kljucem
"""
recnik = {
    "ime": "Resad",
    "prezime": "Spahovic",
    "godina": 1994,
    "ime": "Maida", #uvek se racuna poslednja stavka
    "godina": 1993,  #uzima se poslednja stavka do izlaza
    "ljubav": True,
    "boje": ["crvena", "zuta", "narandzasta", 3]
}
print(recnik)
print(recnik["ime"]) #prvi nacin pristupa
print(recnik["godina"])
x = recnik.get("prezime") #drugi nacin pristupa
y = recnik.get("boje")
print(x)
print(y)
print(len(recnik)) #vraca samo broj originalnih stavki, ne broji duplikate
print(type(recnik))
z = recnik.keys() #vraca listu kljuceva, bez duplikata
print(z)
nerecnik = dict(ime= "Resad", prezime= "Spahovic", godina= 1994)
print(type(nerecnik))
print(nerecnik)

auta = {
    "brend": "Mercedes",
    "model": "E-klasa",
    "godiste": 2003
}
x = auta.keys()
print(x)
auta["boja"] = "crna"
print(x)
auta["motor"] = 1660
print(x)
print(auta)
y = auta.values()
print(y)
print("--------------------------------")
auta = {
    "brend": "Mercedes",
    "model": "E-klasa",
    "godiste": 2003,
    "bojaka": "siva"
}
x = auta.keys() #izdvoj samo kljuceve 
y = auta.values() #izdvoj vrednosti kljuca
print(x)
print(y)
print(auta)
auta["boja"] = "crna" #dodaj u recnik
print(x) #automatski se azurira
print(y) #autmatski se azurira
print(auta)
g = auta.items() #stampa parove, kljuc-vrednost. svaka promena koja se odradi u recniku auta odradice se automatski i ovde
print(g)
if "model" in auta: #provera da li postoji odredjeni kljuc
    print("Postoji stavka model u recniku auta")
print("-------------------------------------------")
auta["brend"] = "audi"
auta["model"] = "A6"
print(auta)
print(auta.items())
print(auta.keys())
print(auta.values())
auta.update({"godiste":2020})
print(auta)
print(auta.items())
auta["karoserija"] = "limuzina" #prvi nacin dodavanja stavki
auta["brvrata"] = 5
auta["karoserija"] = "limuzina"
print(auta)
print(auta.items())
print(auta.keys())
print(auta.values())
if "karoserija" in auta:
    print("Postoji kljuc karoserija u recniku auto")
auta.update({"gorivo": "dizel"}) #ako kljuc koji azuriramo ne postoji u recniku, tada python dodaje taj kljuc i njegovu vreednost kao novu stavku
print(auta)
#auta.pop("karoserija")
auta.pop("gorivo")
print(auta)
auta.popitem() #uklanja poslednju umetnutu stavku
print(auta)
del auta["boja"] #uklanja stavku sa datim kljucom
print(auta)
#del auta
#print(auta)
#auta.clear() prazni recnik ali ne javlja gresku prilikom stampanja ili neke druge radnje
print(auta)
print("------------------------------")
for x in auta:
    print(x) #stampa samo kljuceve u recniku bez vrednosti
print("-------------------------------")
for x in auta:
    print(auta[x]) #stampa samo vrednosti u recniku bez kljuceva
print("---------------------------------")
for x in auta.keys(): #stampa samo kljuceve
    print(x)
print("-----------------------------------")
for x in auta.values(): #stampa samo vrijednosti
    print(x)
print("--------------------------------")
for x, y in auta.items():
    print(x,y) #stampa i kljuc i njegove vrijednosti
kola = auta.copy() #prvi nacin kopiranja recnika sa svim kljucevima i vrednostima
print(kola)
print(auta)
auta["nesto"] = "nesto"
print(kola)
print(auta)
automobili = dict(auta) #drugi nacin pravljenja kopije sa svim kljucevima i vrednostima
print(automobili)
porodica = {
    "otac": {
        "ime": "Resad",
        "prezime": "Spahovic",
        "godina": 1994
    },
    "majka": {
        "ime": "Maida",
        "prezime": "Spahovic",
        "godina": 1993
    },
    "dete": {
        "ime": "Atija",
        "prezime": "Spahovic",
        "godina": 2022
    }
}
print(porodica)
print(porodica["majka"]["godina"])
print(porodica["dete"]["godina"])
print(porodica["otac"]["ime"])