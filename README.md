# alura-criptografia

# AULA 01

## AUTORIZAÇÃO E AUTENTICAÇÃO

- Autorização: você pode fazer isso?
- Autenticação: você é quem alega ser?

## Cifra de César

- Cifra de César, que foi o método usado por Júlio César para criptografar as mensagens mandadas por ele, garantindo um maior sigilo e segurança das informações. A cifra de César consiste em substituir cada letra da mensagem pela letra que está três posições depois dela na ordem alfabética.

## Codificação ASCII

- A codificação mais antiga é a tabela ASCII, mas não contemplava toda diversidade de letras e símbolos para cada sistema de escrita. Daí, especialmente após a popularização da internet, surgiu a necessidade de um padrão de caracteres que englobasse todos os sistemas de escrita. Depois de várias criações de novos padrões, surge o Unicode e os padrões UTF, UTF-12, UTF-32 e UTF-8.

## Usando os métodos charCodeAt() e fromCharCode()

- O charCodeAt() é um método usado para retornar o número que indica o valor Unicode do caractere no índice especificado.

- Sintaxe:

```
    string.charCodeAt(index)
```

- O parâmetro index deve ser um inteiro igual ou maior que 0 e menor que o comprimento da string. Quando não for um número o padrão será 0.

- Vamos observar o charCodeAt() na prática. Criamos uma variável mensagem e testamos em duas versões, a primeira versão recebe um valor string “A” (maiúscula), a segunda recebe um valor string “a” (minúscula):

```
    Exemplo 1:

    const mensagem = "A";
    let codAscii = mensagem.charCodeAt(0);
    console.log(codAscii); // 65


    Exemplo 2:

    const mensagem = "a";
    let codAscii = mensagem.charCodeAt(0);
    console.log(codAscii); // 97Copiar código
```

- Percebe-se que a letra “A” retorna valores diferentes para maiúscula e minúscula. Isso porque o valor retornado do charCodeAt() será sempre um número que representa o valor de unidade de código UTF-16, e na tabela ASCII as letras maiúsculas e minúsculas tem posições e valores diferentes.

# AULA 02 - HASH

- Exemplos: md5, SHA1 e SHA-256
- Cálculo matemático que não tem retorno
- Propriedades:
  - Sem colisões; -- outras palavras não podem gerar o mesmo resultado.
  - Tamanho fixo;
  - Demore um pouco para ser realizado.

## Algoritmos de hash

- MD5: Este é um dos primeiros algoritmos a obter ampla aprovação. Ele foi projetado em 1991 por Ronald Rivest e, na época, foi considerado extremamente seguro. Desde então, hackers descobriram como decodificar o algoritmo e podem fazê-lo em segundos. A maioria dos especialistas acha que não é seguro para uso generalizado, pois é muito fácil de ser desmontado.

  - As colisões contra MD5 podem ser calculadas em segundos, o que torna o algoritmo inadequado para a maioria dos casos de uso em que um hash criptográfico é necessário. MD5 produz um resumo de hash de 128 bits (16 bytes).

- SHA: Os algoritmos da família SHA (Secure Hash Algorithms) são considerados mais seguros. As primeiras versões foram desenvolvidas pelo governo dos Estados Unidos, mas outros programadores se basearam nas estruturas originais e tornaram as variações posteriores mais rigorosas e mais difíceis de quebrar. Em geral, quanto maior o número após as letras "SHA", mais recente o lançamento e mais complexo o programa.

  - Por exemplo, o SHA-3 inclui fontes de aleatoriedade no código, o que o torna muito mais difícil de decifrar do que os anteriores. Tornou-se um algoritmo de hash padrão em 2015 por esse motivo.

  - SHA-0: É uma função hash criptográfica, projetada pela Agência de Segurança Nacional (NSA) dos Estados Unidos, que fornece um hash de 160 bits. O SHA-0 foi retirado logo após a publicação devido a uma "falha significativa" não revelada e substituído pela versão ligeiramente revisada SHA-1.

    A descoberta de fraquezas no design do SHA-0 foi atribuída à NSA, e em 1998 foi confirmado por Antoine Joux e Florent Chabaud um ataque teórico que permite obter uma colisão entre dados criptografados utilizando SHA-0.

  - SHA-1: SHA-1 (Secure Hash Algorithm 1) é uma função de dispersão criptográfica (ou função hash criptográfica) projetada pela Agência de Segurança Nacional (NSA) dos Estados Unidos e é um Padrão Federal de Processamento de Informação dos Estados Unidos publicado pelo Instituto Nacional de Padrões e Tecnologia (NIST).

    - SHA-1 utiliza ao todo um valor de 160 bits, que é equivalente a 20 bytes, para a dispersão criptográfica. Por causa desses valores, a criptografia SHA-1 é conhecida como resumo da mensagem. Cada valor de dispersão do SHA-1 é visto dentro do método como um número hexadecimal constituído por 40 dígitos.

    - Publicada em 1995, SHA-1 é muito similar à SHA-0, mas altera a especificação de dispersão para corrigir as fraquezas alegadas. Entretanto, em 2005, criptoanalistas descobriram ataques sobre SHA-1, sugerindo que o algoritmo poderia não ser seguro o suficiente para uso continuado. O NIST exigiu que várias aplicações utilizadas em agências federais mudassem para SHA-2 depois de 2010 devido à fraqueza descoberta.

  - SHA-2: SHA-2 (Secure Hash Algorithm 2) é um conjunto de funções de hash criptográficas projetadas pela Agência de Segurança Nacional dos Estados Unidos (NSA), publicadas pela primeira vez em 2001. O SHA-2 inclui mudanças significativas em relação ao seu antecessor, o SHA-1, no qual foram encontradas fraquezas.

    - A família SHA-2 consiste em seis funções de hash com resumos (valores de hash) que são SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/ 224, SHA-512/256. Elas são construídas com o intuito de serem muito resistentes à colisão.

    - SHA-256: Esse algoritmo faz parte da família de algoritmos SHA 2 e é uma das mais famosas e seguras funções de hash criptográfica. Publicado em 2001, foi um esforço conjunto entre a NSA (Agência de Segurança Nacional) e o NIST (Instituto Nacional de Padrões e Tecnologia) dos EUA para introduzir um sucessor da família SHA 1, que aos poucos estava perdendo força contra ataques de força bruta. SHA-256 produz um resumo de hash de 256 bits (32 bytes).

      - A título de curiosidade, o Bitcoin utiliza SHA-256 duplo, o que significa que aplica o SHA-256 duas vezes nos dados para garantir ainda mais segurança.

  - SHA-3: SHA-3 (Secure Hash Algorithm 3) foi lançado pelo NIST (Instituto Nacional de Padrões e Tecnologia) dos EUA em 5 de agosto de 2015, ele é o mais recente membro da família de padrões Secure Hash Algorithm.

    - O SHA-3 não se destina a substituir o SHA-2, pois nenhum ataque significativo ao SHA-2 foi demonstrado. Por causa dos ataques bem-sucedidos ao MD5, SHA-0 e SHA-1, o NIST percebeu a necessidade de um hash criptográfico diferente e alternativo, que se tornou SHA-3, que embora faça parte da mesma série de padrões, é internamente diferente da estrutura semelhante a MD5, SHA-1 e SHA-2.

    - SHA-3 fornece os mesmos tamanhos de saída que SHA-2: 224, 256, 384 e 512 bits.

  - RIPEMD-160: é uma função de hash criptográfica de 160 bits. Ele destina-se a ser usado como uma substituição para as funções de hash MD4, MD5 e RIPEMD de 128 bits. Embora as funções RIPEMD sejam menos populares que SHA-1 e SHA-2 , elas são usadas, entre outras, em Bitcoin e outras criptomoedas baseadas em Bitcoin.

  - RIPEMD160 ainda não foi quebrado, mas foi substituído pelos algoritmos de hash SHA-256 e SHA-512 e suas classes derivadas. SHA256 e SHA512 oferecem melhor segurança e desempenho do que RIPEMD160. Utilize RIPEMD160 apenas para compatibilidade com aplicativos e dados herdados.

  - BLAKE3: é uma função de hash criptográfica, anunciada em 9 de janeiro de 2020, que se caracteriza por ser muito mais rápida que MD5, SHA-1, SHA-2, SHA-3 e BLAKE2 (sua antecessora), além de ser mais segura, ao contrário de MD5 e SHA-1, que são rápidas porém menos seguras.

    - Ela foi projetada para aplicações como verificação de integridade de arquivos, autenticação de mensagens e geração de dados para assinaturas digitais criptográficas. O BLAKE3 não foi projetado para hash de senhas, pois visa calcular hashes o mais rápido possível (para senhas, é recomendável utilizar as funções bcrypt, scrypt ou Argon2).

    - O tamanho da saída padrão do BLAKE3 é 256 bits.
