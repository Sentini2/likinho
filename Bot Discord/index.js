require('dotenv').config();
const {
    Client,
    GatewayIntentBits,
    Partials,
    ActionRowBuilder,
    ButtonBuilder,
    ButtonStyle,
    EmbedBuilder,
    ChannelType,
    PermissionsBitField,
    StringSelectMenuBuilder,
    AttachmentBuilder
} = require('discord.js');
const discordTranscripts = require('discord-html-transcripts');
const crypto = require('crypto'); // Para gerar chaves de idempotência na API do MP

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers,
    ],
    partials: [Partials.Message, Partials.Channel, Partials.Reaction]
});

// Configurações (Podem ser movidas para um config.json futuramente)
const TICKET_CATEGORY_ID = process.env.TICKET_CATEGORY_ID || ''; // Preencher no .env ou aqui
const STAFF_ROLE_ID = process.env.STAFF_ROLE_ID || ''; // Preencher no .env ou aqui

client.once('ready', () => {
    console.log(`[BOT] Conectado e operante como ${client.user.tag}!`);
});

// Coleção de Cooldowns para evitar Spam de Tickets
const userCooldowns = new Map();

client.on('messageCreate', async (message) => {
    if (message.author.bot) return;

    // ======== 1. Comando do Painel de Suporte (!painelticket) ========
    if (message.content.toLowerCase() === '!painelticket' && message.member.permissions.has(PermissionsBitField.Flags.Administrator)) {
        const embed = new EmbedBuilder()
            .setTitle('🎫 Central de Atendimento LK Store')
            .setDescription('Selecione no menu abaixo qual o departamento desejado para abrirmos o seu Ticket.')
            .setColor('#ff6600'); // Laranja do LiKinho

        // Criando Dropdown List (Select Menu)
        const row = new ActionRowBuilder()
            .addComponents(
                new StringSelectMenuBuilder()
                    .setCustomId('selecao_ticket')
                    .setPlaceholder('Escolha o motivo do seu Ticket...')
                    .addOptions([
                        {
                            label: 'Suporte',
                            description: 'Preciso de ajuda técnica com o produto',
                            value: 'suporte',
                            emoji: '🛠️'
                        },
                        {
                            label: 'Dúvidas',
                            description: 'Tenho alguma dúvida geral',
                            value: 'duvidas',
                            emoji: '❓'
                        },
                        {
                            label: 'Resgatar Produtos',
                            description: 'Fazer o resgate de uma compra recente',
                            value: 'resgatar',
                            emoji: '📦'
                        },
                        {
                            label: 'Reset de HWID',
                            description: 'Solicitar reset do seu HWID/PC',
                            value: 'hwid',
                            emoji: '💻'
                        },
                        {
                            label: 'Seja Parceiro',
                            description: 'Propostas de parceria com a nossa Store',
                            value: 'parceiro',
                            emoji: '🤝'
                        },
                    ])
            );

        await message.channel.send({ embeds: [embed], components: [row] });
        await message.delete().catch(() => { }); // Apaga o comando !painelticket
    }

    // (Bloco Vendas Removido para index_vendas.js)
});

client.on('interactionCreate', async (interaction) => {

    // ======== LÓGICA DE ABRIR TICKET (DROPDOWN SUPORTE) ========
    if (interaction.isStringSelectMenu() && interaction.customId === 'selecao_ticket') {
        const motivoTicket = interaction.values[0]; // ex: 'suporte', 'hwid'
        const guild = interaction.guild;
        const user = interaction.user;
        const member = interaction.member;

        // VERIFICAÇÃO DE COOLDOWN E TIMEOUT
        const agora = Date.now();
        if (userCooldowns.has(user.id)) {
            const ultimaAbertura = userCooldowns.get(user.id);
            const tempoPassado = agora - ultimaAbertura;

            if (tempoPassado < 30000) { // 30 Segundos
                try {
                    // Aplica um Timeout Nativo de 30 segundos no Usuário (Se o Cargo do Bot for maior)
                    await member.timeout(30 * 1000, 'Abrindo e fechando tickets muito rápido (Anti-Spam)');
                    return interaction.reply({
                        content: '⏳ **Mutado!** Você tentou abrir/fechar tickets de forma abusiva. Aguarde 30 segundos de castigo.',
                        ephemeral: true
                    });
                } catch (err) {
                    // Fallback se o Discord negar permissão
                    return interaction.reply({
                        content: '⏳ Você está indo muito rápido! Aguarde uns segundos antes de solicitar um Ticket.',
                        ephemeral: true
                    });
                }
            }
        }

        // VERIFICAÇÃO DE LIMITE: 1 ticket por usuário
        // Busca todos os canais que terminam com o ID ou nome do usuário
        const ticketsAbertos = guild.channels.cache.filter(c =>
            c.type === ChannelType.GuildText &&
            (c.name.includes(user.username.toLowerCase()) || c.topic === user.id)
        );

        if (ticketsAbertos.size >= 1) {
            return interaction.reply({
                content: `❌ **Atenção!** Você já possui um Ticket Aberto. Feche-o antes de tentar ser atendido novamente.`,
                ephemeral: true
            });
        }

        // Atualiza a tentativa do Cooldown
        userCooldowns.set(user.id, agora);

        await interaction.deferReply({ ephemeral: true });

        // Configurar permissões do novo canal
        const permissoes = [
            {
                id: guild.id, // Everyone (Não ver o canal)
                deny: [PermissionsBitField.Flags.ViewChannel],
            },
            {
                id: user.id, // Usuário que clicou (Ver, Falar e Ler Histórico)
                allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory],
            },
            {
                id: client.user.id, // O próprio Bot
                allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory],
            }
        ];

        // Se houver um cargo STAFF setado
        if (STAFF_ROLE_ID) {
            permissoes.push({
                id: STAFF_ROLE_ID,
                allow: [PermissionsBitField.Flags.ViewChannel, PermissionsBitField.Flags.SendMessages, PermissionsBitField.Flags.ReadMessageHistory],
            });
        }

        try {
            const ticketChannel = await guild.channels.create({
                name: `${motivoTicket}-${user.username}`,
                type: ChannelType.GuildText,
                parent: TICKET_CATEGORY_ID || null,
                topic: user.id, // Usamos o Tópico para guardar silenciosamente o ID de quem abriu
                permissionOverwrites: permissoes
            });

            // Definindo título e cor baseados no motivo
            let titulo = '🎫 Ticket';
            let msgPing = `<@${user.id}>`;

            if (motivoTicket === 'suporte') titulo = '🛠️ Ticket de Suporte';
            else if (motivoTicket === 'duvidas') titulo = '❓ Requisitando Dúvidas';
            else if (motivoTicket === 'resgatar') titulo = '📦 Resgate de Produtos';
            else if (motivoTicket === 'hwid') titulo = '💻 Reset de HWID';
            else if (motivoTicket === 'parceiro') titulo = '🤝 Nova Parceria em Análise';

            // Painel dentro do Ticket
            const embedTicket = new EmbedBuilder()
                .setTitle(titulo)
                .setDescription(`Olá <@${user.id}>! Sua solicitação referente a **${motivoTicket.toUpperCase()}** foi recebida.\n\nAguarde pacientemente, a equipe de suporte logo irá atendê-lo. Descreva melhor o seu problema abaixo.\n\nPara fechar este ticket, um administrador pode clicar no botão **[🔒 Fechar Ticket]**.`)
                .setColor('#2b2d31')
                .setTimestamp();

            const rowTicket = new ActionRowBuilder()
                .addComponents(
                    new ButtonBuilder()
                        .setCustomId('fechar_ticket')
                        .setLabel('Fechar Ticket')
                        .setEmoji('🔒')
                        .setStyle(ButtonStyle.Danger)
                );

            await ticketChannel.send({ content: msgPing, embeds: [embedTicket], components: [rowTicket] });

            await interaction.editReply({ content: `✅ Seu ticket foi criado com sucesso em <#${ticketChannel.id}>!` });
        } catch (err) {
            console.error(err);
            await interaction.editReply({ content: '❌ Ocorreu um erro ao tentar criar o seu ticket. O BOT possui poder de Administrador para Criar Canais e Gerenciar Permissões?' });
        }
    }

    // ======== LÓGICA DE FECHAR TICKET E GERAR TRANSCRIPT ========
    if (interaction.isButton() && interaction.customId === 'fechar_ticket') {
        const canalTicket = interaction.channel;

        // Verifica se quem está tentando fechar é Admin ou Staff com gerência de canais
        if (!interaction.member.permissions.has(PermissionsBitField.Flags.ManageChannels)) {
            return interaction.reply({ content: '⛔ Apenas membros da equipe (com acesso para gerenciar canais) podem fechar o ticket.', ephemeral: true });
        }

        const embedFechando = new EmbedBuilder()
            .setTitle('🔒 Ticket Sendo Fechado')
            .setDescription('Gerando o log do atendimento (Transcript). O canal será deletado em instantes...')
            .setColor('#ff0000');

        await interaction.reply({ embeds: [embedFechando] });

        try {
            // Gerar o Transcript usando HTML
            const attachment = await discordTranscripts.createTranscript(canalTicket, {
                limit: -1,
                returnType: 'attachment',
                filename: `${canalTicket.name}-log.html`,
                saveImages: true,
                poweredBy: false
            });

            // Recuperar o ID do usuário através do Tópico do Canal (Gravado na Criação)
            const idCriador = canalTicket.topic;

            if (idCriador) {
                try {
                    const criador = await client.users.fetch(idCriador);
                    const embedLog = new EmbedBuilder()
                        .setTitle('📜 Transcript de Atendimento')
                        .setDescription(`Seu ticket **${canalTicket.name}** foi encerrado pela nossa equipe de Suporte.\nSegue abaixo o arquivo contendo todo o histórico da conversa para seus registros.`)
                        .setColor('#ff6600')
                        .setTimestamp();

                    await criador.send({ embeds: [embedLog], files: [attachment] });
                } catch (dmErr) {
                    console.log(`[AVISO] Não foi possível enviar DM para o criador do ticket ${canalTicket.name}. DMs trancadas?`);
                }
            }

            // Excluir Canal após todo processamento
            setTimeout(async () => {
                await canalTicket.delete().catch(console.error);
            }, 5000);

        } catch (e) {
            console.error('Erro ao gerar transcript: ', e);
            setTimeout(async () => {
                await canalTicket.delete().catch(console.error);
            }, 3000);
        }
    }
});

// Inicializando o Bot
client.login(process.env.DISCORD_TOKEN);
